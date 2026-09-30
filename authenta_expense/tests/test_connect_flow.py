import base64
import hashlib
import json
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from odoo.exceptions import AccessError, UserError
from odoo.tests import HttpCase, TransactionCase, new_test_user, tagged

from .. import uninstall_hook
from ..models.res_config_settings import (
    DEFAULT_AUTHENTA_URL,
    PARAM_API_KEY,
    PARAM_API_URL,
    PARAM_BASE_URL,
    PARAM_CONNECT_PENDING,
    PARAM_CONNECTED_DB_UUID,
    PARAM_CONNECTED_TENANT,
    PARAM_CONNECTION_STATUS,
    PARAM_INTEGRATION_ID,
)
from ..services.authenta_client import AuthentaAuthError, AuthentaRequestError, AuthentaTransientError
from .test_verification_flow import PNG_1X1, FakeAuthentaClient

NEW_KEY = "api_" + "a" * 64


class FakeConnectClient(FakeAuthentaClient):
    """Fake Authenta API that also redeems connection codes and handles disconnects."""

    def __init__(self):
        super().__init__()
        self.exchanges = []
        self.disconnects = 0

    def exchange_connection_code(self, code, code_verifier, redirect_uri, instance_id):
        self.exchanges.append({"code": code, "verifier": code_verifier, "redirect_uri": redirect_uri, "instance_id": instance_id})
        self._maybe_fail("exchange_connection_code")
        return {"id": "42", "provider": "odoo", "name": "Acme Odoo", "status": "active", "apiKey": {"id": "7", "token": NEW_KEY}}

    def disconnect(self):
        self._maybe_fail("disconnect")
        self.disconnects += 1
        return {}


@tagged("post_install", "-at_install", "authenta")
class TestConnectFlow(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        params = cls.env["ir.config_parameter"].sudo()
        params.set_param("authenta_expense.enabled", "True")
        params.set_param("authenta_expense.base_url", "https://authenta.test")
        params.set_param("web.base.url", "https://odoo.acme.test")
        params.set_param(PARAM_API_KEY, False)
        cls.admin_user = new_test_user(cls.env, login="authenta_admin", groups="base.group_user,base.group_system")
        cls.other_admin = new_test_user(cls.env, login="authenta_admin2", groups="base.group_user,base.group_system")
        cls.employee_user = new_test_user(cls.env, login="authenta_connect_employee", groups="base.group_user")

    def setUp(self):
        super().setUp()
        self.client = FakeConnectClient()
        self.built = []

        def build(_self, base_url, api_key):
            self.built.append((base_url, api_key))
            return self.client

        patcher = patch.object(type(self.env["res.config.settings"]), "_authenta_build_client", build)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.params = self.env["ir.config_parameter"].sudo()
        self.settings_model = self.env["res.config.settings"].with_user(self.admin_user)

    # ---------------------------------------------------------------- helpers

    def _connect(self, user=None):
        settings = self.env["res.config.settings"].with_user(user or self.admin_user).create({})
        action = settings.action_authenta_connect()
        return action, parse_qs(urlparse(action["url"]).query)

    def _pending(self):
        raw = self.params.get_param(PARAM_CONNECT_PENDING)
        return json.loads(raw) if raw else None

    # ---------------------------------------------------------------- connect

    def test_connect_redirects_to_authenta_with_pkce_state_and_instance(self):
        action, query = self._connect()

        self.assertEqual(action["type"], "ir.actions.act_url")
        self.assertEqual(action["target"], "self")
        self.assertTrue(action["url"].startswith("https://authenta.test/api/v1/integrations/connect/authorize?"))
        pending = self._pending()
        self.assertEqual(query["provider"], ["odoo"])
        self.assertEqual(query["redirectUri"], ["https://odoo.acme.test/authenta/connect/callback"])
        self.assertEqual(query["instanceId"], [self.params.get_param("database.uuid")])
        self.assertEqual(query["state"], [pending["state"]])
        self.assertEqual(query["codeChallengeMethod"], ["S256"])
        expected = base64.urlsafe_b64encode(hashlib.sha256(pending["verifier"].encode()).digest()).decode().rstrip("=")
        self.assertEqual(query["codeChallenge"], [expected])
        self.assertNotIn(pending["verifier"], action["url"])
        self.assertEqual(pending["uid"], self.admin_user.id)

    def test_connect_requires_an_administrator(self):
        settings = self.env["res.config.settings"].with_user(self.employee_user)
        with self.assertRaises(AccessError):
            settings._authenta_finish_connection({"code": "x", "state": "y"})

    def test_callback_stores_the_credential_and_clears_the_pending_flow(self):
        _action, query = self._connect()
        pending = self._pending()

        ok, message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertTrue(ok, message)
        self.assertEqual(self.params.get_param(PARAM_API_KEY), NEW_KEY)
        self.assertEqual(self.params.get_param(PARAM_INTEGRATION_ID), "42")
        self.assertEqual(self.params.get_param(PARAM_CONNECTED_TENANT), "Acme")
        self.assertFalse(self.params.get_param(PARAM_CONNECT_PENDING))
        self.assertIn("Connected to Authenta tenant 'Acme'", self.params.get_param(PARAM_CONNECTION_STATUS))
        exchange = self.client.exchanges[0]
        self.assertEqual(exchange["code"], "code-1")
        self.assertEqual(exchange["verifier"], pending["verifier"])
        self.assertEqual(exchange["redirect_uri"], "https://odoo.acme.test/authenta/connect/callback")
        self.assertEqual(exchange["instance_id"], self.params.get_param("database.uuid"))
        self.assertIn(("https://authenta.test", None), self.built)
        self.assertIn(("https://authenta.test", NEW_KEY), self.built)

    def test_callback_rejects_a_wrong_state(self):
        self._connect()

        ok, _message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": "forged-state"})

        self.assertFalse(ok)
        self.assertFalse(self.client.exchanges)
        self.assertFalse(self.params.get_param(PARAM_API_KEY))
        self.assertFalse(self.params.get_param(PARAM_CONNECT_PENDING))

    def test_callback_rejects_a_flow_started_by_another_user(self):
        _action, query = self._connect(user=self.other_admin)

        ok, _message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertFalse(ok)
        self.assertFalse(self.client.exchanges)
        self.assertFalse(self.params.get_param(PARAM_API_KEY))

    def test_callback_rejects_an_expired_flow(self):
        _action, query = self._connect()
        pending = dict(self._pending(), created_at=int(time.time()) - 3600)
        self.params.set_param(PARAM_CONNECT_PENDING, json.dumps(pending))

        ok, _message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertFalse(ok)
        self.assertFalse(self.client.exchanges)

    def test_callback_without_a_started_flow_fails(self):
        ok, _message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": "anything"})

        self.assertFalse(ok)
        self.assertFalse(self.client.exchanges)

    def test_callback_reports_a_cancelled_authorization(self):
        _action, query = self._connect()

        ok, message = self.settings_model._authenta_finish_connection({"error": "access_denied", "state": query["state"][0]})

        self.assertFalse(ok)
        self.assertIn("cancelled", message)
        self.assertFalse(self.client.exchanges)
        self.assertFalse(self.params.get_param(PARAM_CONNECT_PENDING))

    def test_callback_reports_a_rejected_code(self):
        _action, query = self._connect()
        self.client.fail_next["exchange_connection_code"] = AuthentaRequestError(
            "The connection code is invalid, has expired or has already been used", 400, "INTEGRATION_CONNECT_CODE_INVALID"
        )

        ok, message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertFalse(ok)
        self.assertIn("rejected the connection", message)
        self.assertFalse(self.params.get_param(PARAM_API_KEY))

    def test_callback_reports_an_unreachable_authenta(self):
        _action, query = self._connect()
        self.client.fail_next["exchange_connection_code"] = AuthentaTransientError("Could not reach Authenta")

        ok, message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertFalse(ok)
        self.assertIn("could not be reached", message)

    def test_a_code_cannot_be_replayed_after_the_flow_completed(self):
        _action, query = self._connect()
        callback = {"code": "code-1", "state": query["state"][0]}
        self.settings_model._authenta_finish_connection(callback)

        ok, _message = self.settings_model._authenta_finish_connection(callback)

        self.assertFalse(ok)
        self.assertEqual(len(self.client.exchanges), 1)

    # ---------------------------------------------------------------- after connecting

    def _connected(self):
        _action, query = self._connect()
        self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

    def test_test_connection_uses_the_connected_credential(self):
        self._connected()
        self.built.clear()

        result = self.settings_model.create({}).action_authenta_test_connection()

        self.assertEqual(result["params"]["type"], "success")
        self.assertEqual(self.built, [("https://authenta.test", NEW_KEY)])

    def test_test_connection_reports_a_revoked_credential(self):
        self._connected()
        self.client.fail_next["test_connection"] = AuthentaAuthError("API key revoked", 401, "INVALID_API_KEY")

        result = self.settings_model.create({}).action_authenta_test_connection()

        self.assertEqual(result["params"]["type"], "danger")
        self.assertIn("rejected", result["params"]["message"])

    def test_disconnect_revokes_remotely_and_clears_the_credential(self):
        self._connected()

        result = self.settings_model.create({}).action_authenta_disconnect()

        self.assertEqual(result["params"]["type"], "success")
        self.assertEqual(self.client.disconnects, 1)
        self.assertFalse(self.params.get_param(PARAM_API_KEY))
        self.assertFalse(self.params.get_param(PARAM_INTEGRATION_ID))
        self.assertFalse(self.params.get_param(PARAM_CONNECTED_TENANT))

    def test_disconnect_with_an_already_revoked_credential_still_clears_it(self):
        self._connected()
        self.client.fail_next["disconnect"] = AuthentaAuthError("API key revoked", 401, "INVALID_API_KEY")

        result = self.settings_model.create({}).action_authenta_disconnect()

        self.assertEqual(result["params"]["type"], "success")
        self.assertFalse(self.params.get_param(PARAM_API_KEY))

    def test_disconnect_while_authenta_is_unreachable_clears_locally_and_warns(self):
        self._connected()
        self.client.fail_next["disconnect"] = AuthentaTransientError("Could not reach Authenta")

        result = self.settings_model.create({}).action_authenta_disconnect()

        self.assertEqual(result["params"]["type"], "danger")
        self.assertFalse(self.params.get_param(PARAM_API_KEY))

    def test_disconnect_requires_an_administrator(self):
        self._connected()
        with self.assertRaises(AccessError):
            self.env["res.config.settings"].with_user(self.employee_user).create({}).action_authenta_disconnect()

    def test_employee_cannot_change_the_configuration(self):
        with self.assertRaises(AccessError):
            self.env["res.config.settings"].with_user(self.employee_user).create({"authenta_enabled": False})
        with self.assertRaises(AccessError):
            self.env["ir.config_parameter"].with_user(self.employee_user).set_param(PARAM_API_URL, "https://evil.test")
        with self.assertRaises(AccessError):
            self.settings_model.with_user(self.employee_user)._authenta_check_admin()

    def test_employee_cannot_read_the_pending_flow_or_credential(self):
        self._connect()
        params = self.env["ir.config_parameter"].with_user(self.employee_user)
        with self.assertRaises(AccessError):
            params.get_param(PARAM_CONNECT_PENDING)
        with self.assertRaises(AccessError):
            params.get_param(PARAM_API_KEY)

    def test_receipts_are_submitted_with_the_connected_credential(self):
        self._connected()
        self.built.clear()
        employee = self.env["hr.employee"].create({"name": "Connect Employee", "user_id": self.employee_user.id})
        product = self.env["product.product"].create({"name": "Taxi", "can_be_expensed": True, "standard_price": 0})
        expense = self.env["hr.expense"].create({
            "name": "Taxi", "employee_id": employee.id, "product_id": product.id, "total_amount_currency": 25.0,
        })
        self.env["ir.attachment"].create({
            "name": "receipt.png", "raw": PNG_1X1, "mimetype": "image/png", "res_model": "hr.expense", "res_id": expense.id,
        })

        self.env["authenta.verification"]._cron_submit_pending()

        self.assertEqual(len(self.client.create_calls), 1)
        self.assertIn(("https://authenta.test", NEW_KEY), self.built)

    # ---------------------------------------------------------------- URLs

    def test_default_authenta_url_is_used_without_overrides(self):
        self.params.set_param(PARAM_BASE_URL, False)
        action, query = self._connect()
        self.assertTrue(action["url"].startswith(f"{DEFAULT_AUTHENTA_URL}/api/v1/integrations/connect/authorize?"))

        self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertIn((DEFAULT_AUTHENTA_URL, None), self.built)
        self.assertIn((DEFAULT_AUTHENTA_URL, NEW_KEY), self.built)

    def test_api_url_override_is_used_server_side_and_base_url_in_the_browser(self):
        self.params.set_param(PARAM_API_URL, "http://authenta-internal:8080")
        action, query = self._connect()
        self.assertTrue(action["url"].startswith("https://authenta.test/api/v1/integrations/connect/authorize?"))

        ok, message = self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertTrue(ok, message)
        self.assertEqual(self.built, [("http://authenta-internal:8080", None), ("http://authenta-internal:8080", NEW_KEY)])
        self.built.clear()
        self.settings_model.create({}).action_authenta_test_connection()
        self.assertEqual(self.built, [("http://authenta-internal:8080", NEW_KEY)])

    def test_api_url_falls_back_to_the_base_url(self):
        self.assertEqual(self.settings_model._authenta_api_url(), "https://authenta.test")
        self.params.set_param(PARAM_BASE_URL, False)
        self.assertEqual(self.settings_model._authenta_api_url(), DEFAULT_AUTHENTA_URL)

    def test_exchange_uses_the_redirect_uri_the_code_was_issued_for(self):
        _action, query = self._connect()
        self.params.set_param("web.base.url", "https://other-host.acme.test")

        self.settings_model._authenta_finish_connection({"code": "code-1", "state": query["state"][0]})

        self.assertEqual(self.client.exchanges[0]["redirect_uri"], "https://odoo.acme.test/authenta/connect/callback")

    def test_connect_refuses_a_non_https_odoo_address(self):
        self.params.set_param("web.base.url", "http://odoo.acme.test")
        with self.assertRaisesRegex(UserError, "https"):
            self._connect()
        self.assertFalse(self.params.get_param(PARAM_CONNECT_PENDING))

    def test_connect_allows_http_on_localhost(self):
        self.params.set_param("web.base.url", "http://localhost:8069")
        _action, query = self._connect()
        self.assertEqual(query["redirectUri"], ["http://localhost:8069/authenta/connect/callback"])

    # ---------------------------------------------------------------- database binding

    def test_credential_is_bound_to_this_database(self):
        self._connected()
        self.assertEqual(self.params.get_param(PARAM_CONNECTED_DB_UUID), self.params.get_param("database.uuid"))
        self.assertTrue(self.settings_model._authenta_is_connected())

    def test_a_copied_database_does_not_use_the_original_credential(self):
        self._connected()
        self.params.set_param(PARAM_CONNECTED_DB_UUID, "uuid-of-the-original-database")
        self.built.clear()

        self.assertFalse(self.settings_model._authenta_is_connected())
        with self.assertRaisesRegex(UserError, "copy"):
            self.settings_model._authenta_get_client()
        result = self.settings_model.create({}).action_authenta_test_connection()
        self.assertEqual(result["params"]["type"], "danger")
        self.assertFalse(self.built)

    def test_disconnecting_a_copied_database_does_not_revoke_the_original(self):
        self._connected()
        self.params.set_param(PARAM_CONNECTED_DB_UUID, "uuid-of-the-original-database")

        self.settings_model.create({}).action_authenta_disconnect()

        self.assertEqual(self.client.disconnects, 0)
        self.assertFalse(self.params.get_param(PARAM_API_KEY))

    # ---------------------------------------------------------------- logging, uninstall

    def test_connect_failures_log_a_reason_but_no_secrets(self):
        _action, query = self._connect()
        verifier = self._pending()["verifier"]
        with self.assertLogs("odoo.addons.authenta_expense.models.res_config_settings", level="INFO") as logs:
            self.settings_model._authenta_finish_connection({"code": "secret-code-1", "state": "forged-state"})
        output = "\n".join(logs.output)
        self.assertIn("state_mismatch", output)
        self.assertNotIn("secret-code-1", output)
        self.assertNotIn(verifier, output)
        self.assertNotIn(query["state"][0], output)

        _action, query = self._connect()
        self.client.fail_next["exchange_connection_code"] = AuthentaTransientError("Could not reach Authenta (ConnectionError)")
        with self.assertLogs("odoo.addons.authenta_expense.models.res_config_settings", level="INFO") as logs:
            self.settings_model._authenta_finish_connection({"code": "secret-code-2", "state": query["state"][0]})
        output = "\n".join(logs.output)
        self.assertIn("token_exchange_unreachable", output)
        self.assertNotIn("secret-code-2", output)

    def test_successful_connection_never_logs_the_credential(self):
        _action, query = self._connect()
        with self.assertLogs("odoo.addons.authenta_expense", level="DEBUG") as logs:
            self.settings_model._authenta_finish_connection({"code": "secret-code-3", "state": query["state"][0]})
        output = "\n".join(logs.output)
        self.assertNotIn(NEW_KEY, output)
        self.assertNotIn("secret-code-3", output)

    def test_uninstall_removes_the_credential(self):
        self._connected()
        uninstall_hook(self.env)
        self.assertFalse(self.params.get_param(PARAM_API_KEY))
        self.assertFalse(self.params.search([("key", "=like", "authenta_expense.%")]))

    def test_enabled_but_not_connected_sends_and_queues_nothing(self):
        employee = self.env["hr.employee"].create({"name": "Unconnected Employee", "user_id": self.employee_user.id})
        product = self.env["product.product"].create({"name": "Taxi", "can_be_expensed": True, "standard_price": 0})
        expense = self.env["hr.expense"].create({
            "name": "Taxi", "employee_id": employee.id, "product_id": product.id, "total_amount_currency": 25.0,
        })
        self.env["ir.attachment"].create({
            "name": "receipt.png", "raw": PNG_1X1, "mimetype": "image/png", "res_model": "hr.expense", "res_id": expense.id,
        })

        self.env["authenta.verification"]._cron_submit_pending()
        self.env["authenta.verification"]._cron_poll()

        self.assertFalse(expense.authenta_verification_ids)
        self.assertEqual(expense.authenta_status, "none")
        self.assertFalse(self.built)


@tagged("post_install", "-at_install", "authenta")
class TestConnectCallbackAccess(HttpCase):
    def test_callback_is_forbidden_for_employees(self):
        new_test_user(self.env, login="authenta_http_employee", password="authenta_http_employee", groups="base.group_user")
        self.authenticate("authenta_http_employee", "authenta_http_employee")

        response = self.url_open("/authenta/connect/callback?code=x&state=y")

        self.assertEqual(response.status_code, 403)

    def test_callback_returns_the_administrator_to_settings(self):
        new_test_user(self.env, login="authenta_http_admin", password="authenta_http_admin", groups="base.group_user,base.group_system")
        self.authenticate("authenta_http_admin", "authenta_http_admin")

        response = self.url_open("/authenta/connect/callback?error=access_denied&state=y", allow_redirects=False)

        self.assertIn(response.status_code, (302, 303))
        self.assertIn("hr_expense.action_hr_expense_configuration", response.headers["Location"])
