import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from urllib.parse import urlparse

from odoo import _, api, fields, models
from odoo.exceptions import AccessError, UserError

from ..services.authenta_client import (
    AuthentaAuthError,
    AuthentaClient,
    AuthentaError,
    AuthentaForbiddenError,
    build_authorize_url,
)
from ..services.receipt_logic import SUPPORTED_CONTENT_TYPES

_logger = logging.getLogger(__name__)

# The Authenta service this release talks to. Changing the Authenta domain is a module update, not customer configuration;
# PARAM_BASE_URL / PARAM_API_URL are optional technical overrides (developer mode only).
DEFAULT_AUTHENTA_URL = "https://platform-dev.authenta.ai"

PARAM_ENABLED = "authenta_expense.enabled"
# Browser-facing Authenta URL (connect redirect); also the server URL unless PARAM_API_URL is set.
PARAM_BASE_URL = "authenta_expense.base_url"
# Server-to-server Authenta URL, for deployments where Odoo reaches Authenta at another address than browsers do.
PARAM_API_URL = "authenta_expense.api_url"
PARAM_API_KEY = "authenta_expense.api_key"
PARAM_MAX_FILE_MB = "authenta_expense.max_file_size_mb"
PARAM_CONNECTION_STATUS = "authenta_expense.connection_status"
PARAM_CONNECTION_CHECKED_AT = "authenta_expense.connection_checked_at"
PARAM_CONNECT_PENDING = "authenta_expense.connect_pending"
PARAM_INTEGRATION_ID = "authenta_expense.integration_id"
PARAM_CONNECTED_TENANT = "authenta_expense.connected_tenant"
# database.uuid the credential was issued for: a duplicated database gets a new uuid and must not reuse the credential.
PARAM_CONNECTED_DB_UUID = "authenta_expense.connected_db_uuid"

REQUIRED_PERMISSIONS = ("ReadJob", "WriteJob")

CONNECT_CALLBACK_PATH = "/authenta/connect/callback"
CONNECT_PENDING_TTL_SECONDS = 600
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    authenta_enabled = fields.Boolean(string="Verify receipts with Authenta", config_parameter=PARAM_ENABLED)
    authenta_base_url = fields.Char(string="Authenta URL override", config_parameter=PARAM_BASE_URL)
    authenta_api_url = fields.Char(string="Authenta server URL override", config_parameter=PARAM_API_URL)
    # Write-only: never read back into the form so the key is not sent to the browser.
    authenta_api_key = fields.Char(string="Authenta API Key")
    authenta_api_key_set = fields.Boolean(string="API key configured", compute="_compute_authenta_api_key_set")
    authenta_connected_tenant = fields.Char(string="Connected Authenta organization", compute="_compute_authenta_api_key_set")
    authenta_max_file_size_mb = fields.Integer(string="Maximum receipt size (MB)", config_parameter=PARAM_MAX_FILE_MB, default=10)
    authenta_connection_status = fields.Char(string="Connection status", compute="_compute_authenta_connection_status")

    def _compute_authenta_api_key_set(self):
        params = self.env["ir.config_parameter"].sudo()
        is_set = self._authenta_is_connected()
        tenant = params.get_param(PARAM_CONNECTED_TENANT) or ""
        for record in self:
            record.authenta_api_key_set = is_set
            record.authenta_connected_tenant = tenant if is_set else ""

    def _compute_authenta_connection_status(self):
        params = self.env["ir.config_parameter"].sudo()
        status = params.get_param(PARAM_CONNECTION_STATUS) or _("Not tested yet")
        checked_at = params.get_param(PARAM_CONNECTION_CHECKED_AT)
        text = f"{status} ({checked_at} UTC)" if checked_at else status
        for record in self:
            record.authenta_connection_status = text

    def set_values(self):
        super().set_values()
        if self.authenta_api_key:
            params = self.env["ir.config_parameter"].sudo()
            params.set_param(PARAM_API_KEY, self.authenta_api_key.strip())
            params.set_param(PARAM_CONNECTED_DB_UUID, params.get_param("database.uuid"))
            # A manually entered key is not tied to a connect-flow integration.
            params.set_param(PARAM_INTEGRATION_ID, False)
            params.set_param(PARAM_CONNECTED_TENANT, False)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @api.model
    def _authenta_browser_url(self):
        """Authenta URL used by administrators' browsers (connect redirect)."""
        return self.env["ir.config_parameter"].sudo().get_param(PARAM_BASE_URL) or DEFAULT_AUTHENTA_URL

    @api.model
    def _authenta_api_url(self):
        """Authenta URL used by the Odoo server (token exchange, connection test, receipts, polling, disconnect)."""
        params = self.env["ir.config_parameter"].sudo()
        return params.get_param(PARAM_API_URL) or params.get_param(PARAM_BASE_URL) or DEFAULT_AUTHENTA_URL

    @api.model
    def _authenta_is_connected(self):
        """True when a credential is stored and was issued for this database (not for the database it was copied from)."""
        params = self.env["ir.config_parameter"].sudo()
        if not params.get_param(PARAM_API_KEY):
            return False
        bound_uuid = params.get_param(PARAM_CONNECTED_DB_UUID)
        return not bound_uuid or bound_uuid == params.get_param("database.uuid")

    @api.model
    def _authenta_check_admin(self):
        if not self.env.user.has_group("base.group_system"):
            raise AccessError(_("Only administrators can manage the Authenta connection."))

    @api.model
    def _authenta_set_status(self, message):
        params = self.env["ir.config_parameter"].sudo()
        params.set_param(PARAM_CONNECTION_STATUS, message)
        params.set_param(PARAM_CONNECTION_CHECKED_AT, fields.Datetime.to_string(fields.Datetime.now()))

    @api.model
    def _authenta_describe_connection(self, current):
        """Validates the /integrations/current payload. Returns (ok, message)."""
        integration = current.get("integration") or {}
        problems = []
        if integration.get("provider") != "odoo":
            problems.append(_("the key belongs to a '%s' integration, not Odoo", integration.get("provider")))
        if integration.get("status") != "active":
            problems.append(_("the integration is not active"))
        missing = [p for p in REQUIRED_PERMISSIONS if p not in (current.get("permissionNames") or [])]
        if missing:
            problems.append(_("the key is missing permissions: %s", ", ".join(missing)))

        task_types = {t.get("contentType"): t for t in current.get("taskTypes") or []}
        usable = [ct for ct in SUPPORTED_CONTENT_TYPES if task_types.get(ct, {}).get("available")]
        unusable = [ct for ct in SUPPORTED_CONTENT_TYPES if ct not in usable]
        if not usable:
            problems.append(_("no receipt type (JPEG, PNG, PDF) is mapped to an available Authenta task type"))

        tenant = (current.get("tenant") or {}).get("name") or "?"
        if problems:
            return False, _("Error: %s.", "; ".join(problems))
        message = _("Connected to Authenta tenant '%(tenant)s' via integration '%(name)s'.", tenant=tenant, name=integration.get("name"))
        if unusable:
            message += " " + _("Receipts of type %s are not mapped and will be marked as verification errors.", ", ".join(unusable))
        return True, message

    @api.model
    def _authenta_check_connection(self, client):
        """Calls Authenta's connection endpoint with the given client and records an administrator-facing status."""
        ok = False
        try:
            current = client.test_connection()
            ok, message = self._authenta_describe_connection(current)
            tenant = (current.get("tenant") or {}).get("name")
            if tenant:
                self.env["ir.config_parameter"].sudo().set_param(PARAM_CONNECTED_TENANT, tenant)
        except AuthentaError as exc:
            hints = {
                "auth": _("the API key was rejected (wrong, rotated or revoked)"),
                "forbidden": _("access denied — the integration may be disabled or the Authenta account suspended"),
                "transient": _("Authenta could not be reached — check that this Odoo server can reach the internet and try again"),
            }
            message = _("Error: %s.", hints.get(exc.kind, exc.message))
        self._authenta_set_status(message)
        _logger.info("Authenta connection test finished: ok=%s", ok)
        return ok, message

    @api.model
    def _authenta_notification(self, ok, message):
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": _("Authenta connection"),
                "message": message,
                "type": "success" if ok else "danger",
                "sticky": not ok,
                "next": {"type": "ir.actions.client", "tag": "reload"},
            },
        }

    def action_authenta_test_connection(self):
        """Saves the settings, calls Authenta's connection endpoint and records an administrator-facing status."""
        self.ensure_one()
        self._authenta_check_admin()
        self.set_values()
        try:
            client = self._authenta_get_client()
        except UserError as exc:
            message = _("Error: %s", exc.args[0])
            self._authenta_set_status(message)
            return self._authenta_notification(False, message)
        ok, message = self._authenta_check_connection(client)
        return self._authenta_notification(ok, message)

    def action_authenta_connect(self):
        """Starts the connect flow: sends the administrator to Authenta to log in and authorize this Odoo database."""
        self.ensure_one()
        self._authenta_check_admin()
        self.set_values()
        params = self.env["ir.config_parameter"].sudo()
        redirect_uri = self._authenta_redirect_uri()
        callback = urlparse(redirect_uri)
        if not callback.hostname or (callback.scheme != "https" and not (callback.scheme == "http" and callback.hostname in LOOPBACK_HOSTS)):
            raise UserError(_(
                "Odoo's web address (%s) must use https for Authenta to send you back after connecting. "
                "Open Odoo through its https address and try again.", redirect_uri.removesuffix(CONNECT_CALLBACK_PATH) or "?"
            ))

        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        pending = {
            "state": state,
            "verifier": verifier,
            "uid": self.env.uid,
            "created_at": int(time.time()),
            # The token exchange must present exactly the redirect URI Authenta issued the code for.
            "redirect_uri": redirect_uri,
        }
        params.set_param(PARAM_CONNECT_PENDING, json.dumps(pending))
        _logger.info("Authenta connect flow started by user %s", self.env.uid)

        url = build_authorize_url(self._authenta_browser_url(), {
            "provider": "odoo",
            "redirectUri": redirect_uri,
            "state": state,
            "codeChallenge": challenge,
            "codeChallengeMethod": "S256",
            "instanceId": params.get_param("database.uuid"),
            "instanceName": (self.env.company.name or "Odoo")[:100],
        })
        return {"type": "ir.actions.act_url", "url": url, "target": "self"}

    @api.model
    def _authenta_redirect_uri(self):
        base = self.env["ir.config_parameter"].sudo().get_param("web.base.url") or ""
        return f"{base.rstrip('/')}{CONNECT_CALLBACK_PATH}"

    @api.model
    def _authenta_finish_connection(self, query):
        """Completes the connect flow from the callback query. Returns (ok, message); secrets are never logged."""
        self._authenta_check_admin()
        params = self.env["ir.config_parameter"].sudo()
        raw_pending = params.get_param(PARAM_CONNECT_PENDING)
        # Single use: whatever happens next, this pending flow cannot be completed twice.
        params.set_param(PARAM_CONNECT_PENDING, False)

        def fail(reason, message):
            # `reason` is a fixed diagnostic code for the server log; codes, verifiers and keys are never logged.
            self._authenta_set_status(message)
            log = _logger.info if reason == "cancelled" else _logger.warning
            log("Authenta connect flow did not complete: %s", reason)
            return False, message

        try:
            pending = json.loads(raw_pending) if raw_pending else None
        except ValueError:
            pending = None
        if query.get("error"):
            if query.get("error") == "access_denied":
                return fail("cancelled", _("Connection cancelled in Authenta."))
            return fail("authorize_error", _("Error: Authenta did not authorize the connection (%s).", query.get("error")))
        if not pending or not isinstance(pending, dict):
            return fail("no_pending_flow", _("Error: no connection was started from this Odoo database. Click Connect again."))
        if pending.get("uid") != self.env.uid:
            return fail("other_user", _("Error: the connection was started by another user. Click Connect again."))
        if not hmac.compare_digest(str(pending.get("state") or ""), str(query.get("state") or "")):
            return fail("state_mismatch", _("Error: the connection request could not be verified. Click Connect again."))
        if time.time() - int(pending.get("created_at") or 0) > CONNECT_PENDING_TTL_SECONDS:
            return fail("expired", _("Error: the connection request expired. Click Connect again."))
        if not query.get("code"):
            return fail("missing_code", _("Error: Authenta did not return a connection code. Click Connect again."))

        api_url = self._authenta_api_url()
        redirect_uri = pending.get("redirect_uri") or self._authenta_redirect_uri()
        try:
            result = self._authenta_build_client(api_url, None).exchange_connection_code(
                query["code"], pending["verifier"], redirect_uri, params.get_param("database.uuid")
            )
        except AuthentaError as exc:
            if exc.kind == "transient":
                return fail(
                    f"token_exchange_unreachable ({exc.message})",
                    _("Error: Authenta could not be reached. Click Connect again."),
                )
            return fail(
                f"token_exchange_rejected (HTTP {exc.status_code} {exc.code})",
                _("Error: Authenta rejected the connection (%s). Click Connect again.", exc.message),
            )

        api_key = (result.get("apiKey") or {}).get("token")
        if not api_key:
            return fail("no_credential", _("Error: Authenta did not return a credential. Click Connect again."))
        params.set_param(PARAM_API_KEY, api_key)
        params.set_param(PARAM_CONNECTED_DB_UUID, params.get_param("database.uuid"))
        params.set_param(PARAM_INTEGRATION_ID, str(result.get("id") or ""))
        params.set_param(PARAM_CONNECTED_TENANT, False)
        _logger.info("Authenta integration %s connected", result.get("id"))
        return self._authenta_check_connection(self._authenta_build_client(api_url, api_key))

    def action_authenta_disconnect(self):
        """Revokes this database's Authenta credential (best effort) and removes it from Odoo."""
        self.ensure_one()
        self._authenta_check_admin()
        params = self.env["ir.config_parameter"].sudo()
        message = _("Disconnected from Authenta.")
        ok = True
        if not self._authenta_is_connected():
            # Nothing to revoke, or a credential copied from another database: revoking it would disconnect that database.
            pass
        else:
            try:
                self._authenta_get_client().disconnect()
            except (AuthentaAuthError, AuthentaForbiddenError):
                pass  # Already revoked or disabled on the Authenta side.
            except AuthentaError:
                ok = False
                message = _(
                    "Disconnected in Odoo, but Authenta could not be reached to revoke the credential. "
                    "Disable the integration in Authenta."
                )
        for key in (PARAM_API_KEY, PARAM_INTEGRATION_ID, PARAM_CONNECTED_TENANT, PARAM_CONNECTED_DB_UUID):
            params.set_param(key, False)
        self._authenta_set_status(message)
        _logger.info("Authenta disconnected (revoked remotely: %s)", ok)
        return self._authenta_notification(ok, message)

    @api.model
    def _authenta_build_client(self, api_url, api_key):
        """Client factory (patched in tests). Without an API key the client can only redeem connection codes."""
        if api_key:
            return AuthentaClient(api_url, api_key)
        return AuthentaClient.unauthenticated(api_url)

    @api.model
    def _authenta_get_client(self):
        """Builds a server-side client from the stored configuration (sudo: credentials are admin-only)."""
        params = self.env["ir.config_parameter"].sudo()
        if not params.get_param(PARAM_API_KEY):
            raise UserError(_("Authenta is not connected. An administrator must connect it in the Expenses settings."))
        if not self._authenta_is_connected():
            raise UserError(_(
                "This database is a copy of the database that was connected to Authenta. "
                "An administrator must connect it to Authenta again."
            ))
        return self._authenta_build_client(self._authenta_api_url(), params.get_param(PARAM_API_KEY))
