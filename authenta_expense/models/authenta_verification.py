import json
import logging
import threading
from datetime import timedelta

from odoo import _, _lt, api, fields, models
from odoo.exceptions import UserError
from odoo.tools.pdf import PdfFileReader

from ..services.authenta_client import AuthentaError
from ..services.receipt_logic import (
    FAILED_JOB_STATUSES,
    MAX_PROCESSING_AGE,
    MAX_TRANSIENT_ATTEMPTS,
    NON_TERMINAL_JOB_STATUSES,
    PDF_CONTENT_TYPE,
    ReceiptError,
    backoff_seconds,
    build_external_reference,
    build_idempotency_key,
    count_pdf_pages,
    interpret_result,
)
from .res_config_settings import PARAM_ENABLED, PARAM_MAX_FILE_MB

_logger = logging.getLogger(__name__)

SUBMIT_BATCH_SIZE = 20
POLL_BATCH_SIZE = 50
FIRST_POLL_DELAY = timedelta(seconds=30)
MAX_POLL_INTERVAL_SECONDS = 900

CONFIG_ERROR_MESSAGES = {
    "auth": _lt("Authenta rejected the integration API key. An administrator must update the Authenta settings."),
    "forbidden": _lt("Authenta denied access (integration disabled, missing permission or suspended account). An administrator must check the integration."),
    "billing": _lt("The Authenta account has insufficient credits. An administrator must top up the Authenta wallet, then retry."),
}


class AuthentaVerification(models.Model):
    _name = "authenta.verification"
    _description = "Authenta Receipt Verification"
    _order = "create_date desc, id desc"
    _rec_name = "attachment_name"

    expense_id = fields.Many2one("hr.expense", string="Expense", required=True, ondelete="cascade", index=True, readonly=True)
    employee_id = fields.Many2one(related="expense_id.employee_id", store=True, string="Employee")
    company_id = fields.Many2one(related="expense_id.company_id", store=True, string="Company")
    attachment_id = fields.Many2one("ir.attachment", string="Receipt", ondelete="set null", index=True, readonly=True)
    attachment_name = fields.Char(string="Receipt Name", readonly=True)
    mimetype = fields.Char(string="File Type", readonly=True)
    checksum = fields.Char(readonly=True)
    attempt = fields.Integer(string="Verification Attempt", default=1, readonly=True)
    superseded = fields.Boolean(
        string="Superseded", default=False, readonly=True, help="Replaced by a newer verification attempt of the same receipt."
    )

    state = fields.Selection(
        selection=[
            ("pending", "Pending"),
            ("submitted", "Submitted"),
            ("processing", "Processing"),
            ("completed", "Completed"),
            ("failed", "Failed"),
            ("error", "Error"),
        ],
        default="pending",
        required=True,
        readonly=True,
        index=True,
    )
    verdict = fields.Selection(
        selection=[("real", "Real"), ("fake", "Fake"), ("unknown", "Unknown")],
        default="unknown",
        required=True,
        readonly=True,
    )
    last_error = fields.Text(string="Last Error", readonly=True)

    authenta_job_id = fields.Char(string="Authenta Job ID", readonly=True, index=True, groups="hr_expense.group_hr_expense_manager")
    idempotency_key = fields.Char(readonly=True, groups="hr_expense.group_hr_expense_manager")
    external_reference = fields.Char(readonly=True, groups="hr_expense.group_hr_expense_manager")
    result = fields.Text(string="Authenta Result", readonly=True, groups="hr_expense.group_hr_expense_manager")
    attempts = fields.Integer(string="Failed Attempts", default=0, readonly=True, groups="hr_expense.group_hr_expense_manager")
    poll_count = fields.Integer(default=0, readonly=True, groups="hr_expense.group_hr_expense_manager")
    next_attempt_at = fields.Datetime(readonly=True, index=True, groups="hr_expense.group_hr_expense_manager")
    submitted_at = fields.Datetime(readonly=True)
    completed_at = fields.Datetime(readonly=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @api.model
    def _is_enabled(self):
        """The administrator opted in to receipt verification (approval gating applies)."""
        return bool(self.env["ir.config_parameter"].sudo().get_param(PARAM_ENABLED))

    @api.model
    def _is_active(self):
        """Opted in and connected: only then are receipts queued for, and sent to, Authenta."""
        return self._is_enabled() and self.env["res.config.settings"]._authenta_is_connected()

    def _lock_due(self, states):
        """Row-locks this verification if it is still in `states` and due, skipping it when another worker holds it.

        Guards against the same record being processed concurrently (scheduled run + manual run, several workers).
        """
        self.ensure_one()
        self.flush_recordset(["state", "next_attempt_at"])
        self.env.cr.execute(
            """SELECT id FROM authenta_verification
                WHERE id = %s AND state IN %s AND (next_attempt_at IS NULL OR next_attempt_at <= %s)
                  FOR UPDATE SKIP LOCKED""",
            (self.id, tuple(states), fields.Datetime.now()),
        )
        locked = bool(self.env.cr.fetchone())
        self.invalidate_recordset()
        return locked

    @api.model
    def _db_uuid(self):
        return self.env["ir.config_parameter"].sudo().get_param("database.uuid")

    @api.model
    def _auto_commit(self):
        """Commit after each record in crons so one failure does not roll back others (never inside tests)."""
        if not getattr(threading.current_thread(), "testing", False):
            self.env.cr.commit()  # pylint: disable=invalid-commit

    @api.model
    def _trigger_submission(self):
        cron = self.env.ref("authenta_expense.ir_cron_authenta_submit", raise_if_not_found=False)
        if cron:
            cron.sudo()._trigger()

    def _notify_expense(self, body):
        for record in self:
            record.expense_id.sudo().message_post(body=body, subtype_xmlid="mail.mt_note")

    # ------------------------------------------------------------------
    # Creation (called from the ir.attachment hooks)
    # ------------------------------------------------------------------

    @api.model
    def _create_for_attachments(self, attachments):
        """Creates a pending verification for each new expense receipt and schedules background submission."""
        if not self._is_active():
            return self.browse()
        receipts = attachments.filtered(lambda a: a.res_model == "hr.expense" and a.res_id and not a.res_field)
        if not receipts:
            return self.browse()
        current = self.sudo().search([("attachment_id", "in", receipts.ids), ("superseded", "=", False)])
        for verification in current:
            # A receipt re-linked to another expense takes its verification (and result) along; no new Authenta job.
            if verification.attachment_id.res_id != verification.expense_id.id:
                expense = self.env["hr.expense"].sudo().browse(verification.attachment_id.res_id).exists()
                if expense:
                    verification.write({"expense_id": expense.id})
        existing = current.mapped("attachment_id")
        vals_list = []
        for attachment in receipts - existing:
            expense = self.env["hr.expense"].sudo().browse(attachment.res_id).exists()
            if not expense:
                continue
            vals_list.append({
                "expense_id": expense.id,
                "attachment_id": attachment.id,
                "attachment_name": attachment.name,
                "mimetype": attachment.mimetype,
                "checksum": attachment.checksum,
            })
        records = self.sudo().create(vals_list) if vals_list else self.browse()
        if records:
            self._trigger_submission()
        return records

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _mark_error(self, message):
        self.sudo().write({"state": "error", "last_error": message, "next_attempt_at": False})
        self._notify_expense(_("Authenta could not verify receipt '%(name)s': %(reason)s", name=self.attachment_name, reason=message))

    def _mark_transient_failure(self, message):
        """Bounded retry: exponential backoff, then give up with an error."""
        self.ensure_one()
        attempts = self.sudo().attempts + 1
        if attempts >= MAX_TRANSIENT_ATTEMPTS:
            self.sudo().write({"attempts": attempts})
            self._mark_error(_("%(reason)s (gave up after %(count)s attempts)", reason=message, count=attempts))
            return
        next_at = fields.Datetime.now() + timedelta(seconds=backoff_seconds(attempts))
        self.sudo().write({"attempts": attempts, "last_error": message, "next_attempt_at": next_at})

    def _handle_api_error(self, error):
        if error.retryable:
            self._mark_transient_failure(error.message)
        elif error.kind in CONFIG_ERROR_MESSAGES:
            self._mark_error(str(CONFIG_ERROR_MESSAGES[error.kind]))
        elif error.kind == "conflict":
            self._mark_error(_("Authenta refused the request as a conflicting duplicate: %s", error.message))
        elif error.status_code == 404 and self.sudo().authenta_job_id:
            self.sudo().write({"state": "failed", "last_error": _("The Authenta job no longer exists."), "next_attempt_at": False})
        else:
            self._mark_error(error.message)

    def _apply_job(self, job):
        """Maps an Authenta job (from create/replay or polling) onto this verification."""
        self.ensure_one()
        record = self.sudo()
        status = job.get("status")
        now = fields.Datetime.now()
        if status in NON_TERMINAL_JOB_STATUSES:
            if record.submitted_at and now - record.submitted_at > MAX_PROCESSING_AGE:
                self._mark_error(_("Authenta did not finish verifying the receipt within 24 hours."))
                return
            poll_count = record.poll_count + 1
            delay = min(60 * (2 ** min(poll_count - 1, 4)), MAX_POLL_INTERVAL_SECONDS)
            record.write({"state": "processing", "poll_count": poll_count, "next_attempt_at": now + timedelta(seconds=delay)})
        elif status == "completed":
            result = job.get("result")
            verdict = interpret_result(result)
            record.write({
                "state": "completed",
                "verdict": verdict,
                "result": json.dumps(result, sort_keys=True) if result is not None else False,
                "completed_at": now,
                "next_attempt_at": False,
                "last_error": False if verdict != "unknown" else _("Authenta returned a result that could not be interpreted."),
            })
            messages = {
                "real": _("Authenta verified receipt '%s' as authentic.", record.attachment_name),
                "fake": _("Authenta flagged receipt '%s' as FAKE. The expense cannot be approved.", record.attachment_name),
                "unknown": _("Authenta could not classify receipt '%s'. The expense cannot be approved until it is re-verified.", record.attachment_name),
            }
            self._notify_expense(messages[verdict])
        elif status in FAILED_JOB_STATUSES:
            reason = _("Authenta could not process the receipt (job %s). A processing failure is not evidence of fraud; re-verify the receipt.", status)
            record.write({"state": "failed", "last_error": reason, "next_attempt_at": False})
            self._notify_expense(_("Receipt '%(name)s': %(reason)s", name=record.attachment_name, reason=reason))
        else:
            self._mark_transient_failure(_("Unexpected Authenta job status '%s'", status))

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def _prepare_submission(self, task_types):
        """Validates the receipt locally. Returns (task_type, data, page_count) or raises ReceiptError."""
        self.ensure_one()
        attachment = self.sudo().attachment_id
        if not attachment:
            raise ReceiptError(_("The receipt was removed before it could be verified."))
        mimetype = attachment.mimetype
        task_type = task_types.get(mimetype)
        if not task_type or not task_type.get("available"):
            raise ReceiptError(_("Receipts of type '%s' are not supported (JPEG, PNG and PDF are).", mimetype or _("unknown")))
        max_mb = int(self.env["ir.config_parameter"].sudo().get_param(PARAM_MAX_FILE_MB) or 10)
        if attachment.file_size > max_mb * 1024 * 1024:
            raise ReceiptError(_("The receipt is larger than %s MB.", max_mb))
        data = attachment.raw
        if not data:
            raise ReceiptError(_("The receipt file is empty."))
        page_count = count_pdf_pages(data, PdfFileReader) if mimetype == PDF_CONTENT_TYPE else None
        return task_type, data, page_count

    def _submit(self, client, task_types):
        """Creates (or idempotently resumes) the Authenta job, uploads the receipt and finalizes it."""
        self.ensure_one()
        record = self.sudo()
        try:
            task_type, data, page_count = self._prepare_submission(task_types)
        except ReceiptError as exc:
            self._mark_error(str(exc))
            return

        db_uuid = self._db_uuid()
        key = record.idempotency_key or build_idempotency_key(db_uuid, record.id, record.checksum)
        reference = record.external_reference or build_external_reference(db_uuid, record.attachment_id.id)
        metadata = {
            "source": "odoo",
            "expenseId": str(record.expense_id.id),
            "attachmentId": str(record.attachment_id.id),
            "verificationId": str(record.id),
        }
        record.write({"idempotency_key": key, "external_reference": reference})
        try:
            job, inputs = client.create_job(
                task_type_id=task_type["taskTypeId"],
                slot_name=task_type.get("slotName") or "original",
                file_name=record.attachment_name or "receipt",
                content_type=record.attachment_id.mimetype,
                size_bytes=len(data),
                idempotency_key=key,
                external_reference=reference,
                external_metadata=metadata,
                page_count=page_count,
            )
            record.write({"authenta_job_id": str(job.get("id"))})
            status = job.get("status")
            if status == "initiated":
                if not inputs:
                    raise AuthentaError("Authenta returned no upload URL for an initiated job")
                for upload in inputs:
                    client.upload_file(upload["uploadUrl"], data, record.attachment_id.mimetype)
                client.finalize_job(job["id"])
                status = "queued"
        except AuthentaError as exc:
            if type(exc) is AuthentaError:  # unexpected shape: retry like a transient failure
                self._mark_transient_failure(exc.message)
            else:
                self._handle_api_error(exc)
            return

        now = fields.Datetime.now()
        record.write({
            "state": "submitted",
            "submitted_at": record.submitted_at or now,
            "attempts": 0,
            "last_error": False,
            "next_attempt_at": now + FIRST_POLL_DELAY,
        })
        if status not in NON_TERMINAL_JOB_STATUSES:
            self._apply_job(job)

    @api.model
    def _get_task_types(self, client):
        current = client.test_connection()
        return {t.get("contentType"): t for t in current.get("taskTypes") or []}

    @api.model
    def _cron_submit_pending(self, limit=SUBMIT_BATCH_SIZE):
        """Cron: submits pending receipts whose next attempt is due."""
        if not self._is_active():
            return
        now = fields.Datetime.now()
        domain = [("state", "=", "pending"), "|", ("next_attempt_at", "=", False), ("next_attempt_at", "<=", now)]
        records = self.sudo().search(domain, limit=limit, order="id")
        if not records:
            return
        try:
            client = self.env["res.config.settings"]._authenta_get_client()
            task_types = self._get_task_types(client)
        except UserError as exc:
            _logger.warning("Authenta submission skipped: %s", exc)
            return
        except AuthentaError as exc:
            if exc.retryable:
                _logger.warning("Authenta unreachable, submission postponed: %s", exc.message)
                return
            for record in records:
                record._handle_api_error(exc)
            self._auto_commit()
            return
        for record in records:
            if not record._lock_due(("pending",)):
                continue
            try:
                record._submit(client, task_types)
            except Exception:
                _logger.exception("Unexpected error submitting Authenta verification %s", record.id)
                self.env.cr.rollback()
                record._mark_transient_failure(_("Unexpected error while submitting the receipt."))
            self._auto_commit()

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def _poll(self, client):
        self.ensure_one()
        try:
            job = client.get_job(self.sudo().authenta_job_id)
        except AuthentaError as exc:
            self._handle_api_error(exc)
            return
        self._apply_job(job)

    @api.model
    def _cron_poll(self, limit=POLL_BATCH_SIZE):
        """Cron: polls Authenta for submitted/processing verifications whose next poll is due."""
        now = fields.Datetime.now()
        domain = [
            ("state", "in", ("submitted", "processing")),
            ("authenta_job_id", "!=", False),
            "|",
            ("next_attempt_at", "=", False),
            ("next_attempt_at", "<=", now),
        ]
        records = self.sudo().search(domain, limit=limit, order="next_attempt_at, id")
        if not records:
            return
        # Jobs already submitted are still collected when verification is switched off, but not without a credential.
        if not self.env["res.config.settings"]._authenta_is_connected():
            _logger.debug("Authenta polling skipped: not connected")
            return
        client = self.env["res.config.settings"]._authenta_get_client()
        for record in records:
            if not record._lock_due(("submitted", "processing")):
                continue
            try:
                record._poll(client)
            except Exception:
                _logger.exception("Unexpected error polling Authenta verification %s", record.id)
                self.env.cr.rollback()
                record._mark_transient_failure(_("Unexpected error while checking the verification result."))
            self._auto_commit()

    # ------------------------------------------------------------------
    # Manager actions
    # ------------------------------------------------------------------

    def _check_manager(self):
        if not self.env.user.has_group("hr_expense.group_hr_expense_manager"):
            raise UserError(_("Only expense administrators can manage Authenta verifications."))

    def action_retry(self):
        """Retries errored verifications with the same idempotency key (no duplicate Authenta job)."""
        self._check_manager()
        if not self._is_active():
            raise UserError(_("Authenta receipt verification is disabled or not connected."))
        for record in self.sudo().filtered(lambda r: r.state == "error" and not r.superseded):
            state = "submitted" if record.authenta_job_id else "pending"
            record.write({"state": state, "attempts": 0, "last_error": False, "next_attempt_at": False})
        self._trigger_submission()
        return True

    def action_reverify(self):
        """Starts a new verification attempt (new idempotency key) and keeps the previous one as history."""
        self._check_manager()
        if not self._is_active():
            raise UserError(_("Authenta receipt verification is disabled or not connected."))
        new_records = self.browse()
        for record in self.sudo().filtered(lambda r: not r.superseded):
            attachment = record.attachment_id
            if not attachment:
                raise UserError(_("Receipt '%s' was removed and cannot be re-verified.", record.attachment_name))
            record.write({"superseded": True, "next_attempt_at": False})
            new_records |= self.sudo().create({
                "expense_id": record.expense_id.id,
                "attachment_id": attachment.id,
                "attachment_name": attachment.name,
                "mimetype": attachment.mimetype,
                "checksum": attachment.checksum,
                "attempt": record.attempt + 1,
            })
        self._trigger_submission()
        return True
