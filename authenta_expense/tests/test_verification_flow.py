import base64
from datetime import timedelta
from unittest.mock import patch

from odoo import fields
from odoo.exceptions import AccessError, UserError
from odoo.tests import TransactionCase, new_test_user, tagged

from ..services.authenta_client import (
    AuthentaAuthError,
    AuthentaBillingError,
    AuthentaTransientError,
    AuthentaUploadError,
)
from ..services.receipt_logic import MAX_TRANSIENT_ATTEMPTS
from .test_receipt_logic import make_pdf

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

TASK_TYPES = [
    {"contentType": "application/pdf", "taskTypeId": "12", "slug": "pdf-tampering-detection", "slotName": "original", "available": True},
    {"contentType": "image/jpeg", "taskTypeId": "6", "slug": "document-intelligence", "slotName": "original", "available": True},
    {"contentType": "image/png", "taskTypeId": "6", "slug": "document-intelligence", "slotName": "original", "available": True},
]


class FakeAuthentaClient:
    """In-memory stand-in for the Authenta API that mimics idempotent job creation."""

    def __init__(self):
        self.jobs = {}
        self.jobs_by_key = {}
        self.create_calls = []
        self.uploads = []
        self.finalized = []
        self.fail_next = {}

    def _maybe_fail(self, operation):
        error = self.fail_next.pop(operation, None)
        if error:
            raise error

    def test_connection(self):
        self._maybe_fail("test_connection")
        return {
            "tenant": {"id": "t-1", "name": "Acme", "type": "enterprise"},
            "integration": {"id": "1", "provider": "odoo", "name": "Acme Odoo", "status": "active"},
            "permissions": 3,
            "permissionNames": ["ReadJob", "WriteJob"],
            "taskTypes": TASK_TYPES,
        }

    def create_job(self, **kwargs):
        self.create_calls.append(kwargs)
        self._maybe_fail("create_job")
        key = kwargs["idempotency_key"]
        job = self.jobs_by_key.get(key)
        if not job:
            job_id = str(len(self.jobs) + 100)
            job = {"id": job_id, "status": "initiated", "result": None}
            self.jobs[job_id] = job
            self.jobs_by_key[key] = job
        inputs = [{"slotName": "original", "uploadUrl": f"https://storage.test/upload/{job['id']}/{len(self.create_calls)}"}]
        return dict(job), inputs if job["status"] == "initiated" else []

    def upload_file(self, upload_url, data, content_type):
        self._maybe_fail("upload_file")
        self.uploads.append((upload_url, len(data), content_type))

    def finalize_job(self, job_id):
        self._maybe_fail("finalize_job")
        self.finalized.append(job_id)
        self.jobs[job_id]["status"] = "queued"

    def get_job(self, job_id):
        self._maybe_fail("get_job")
        return dict(self.jobs[job_id])

    def complete(self, job_id, result):
        self.jobs[job_id].update(status="completed", result=result)


@tagged("post_install", "-at_install", "authenta")
class TestVerificationFlow(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        params = cls.env["ir.config_parameter"].sudo()
        params.set_param("authenta_expense.enabled", "True")
        params.set_param("authenta_expense.base_url", "https://authenta.test")
        params.set_param("authenta_expense.api_key", "api_test")

        cls.employee_user = new_test_user(cls.env, login="authenta_employee", groups="base.group_user")
        cls.other_user = new_test_user(cls.env, login="authenta_other", groups="base.group_user")
        cls.manager_user = new_test_user(
            cls.env, login="authenta_manager", groups="base.group_user,hr_expense.group_hr_expense_manager"
        )
        cls.employee = cls.env["hr.employee"].create({"name": "Receipt Employee", "user_id": cls.employee_user.id})
        cls.other_employee = cls.env["hr.employee"].create({"name": "Other Employee", "user_id": cls.other_user.id})
        cls.product = cls.env["product.product"].create({"name": "Taxi", "can_be_expensed": True, "standard_price": 0})

    def setUp(self):
        super().setUp()
        self.client = FakeAuthentaClient()
        patcher = patch.object(type(self.env["res.config.settings"]), "_authenta_get_client", lambda _self: self.client)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---------------------------------------------------------------- helpers

    def _expense(self, employee=None, name="Taxi"):
        return self.env["hr.expense"].create({
            "name": name,
            "employee_id": (employee or self.employee).id,
            "product_id": self.product.id,
            "total_amount_currency": 25.0,
        })

    def _attach(self, expense, name="receipt.png", data=PNG_1X1, mimetype="image/png"):
        return self.env["ir.attachment"].create({
            "name": name,
            "raw": data,
            "mimetype": mimetype,
            "res_model": "hr.expense",
            "res_id": expense.id,
        })

    def _verification(self, attachment):
        return self.env["authenta.verification"].sudo().search([("attachment_id", "=", attachment.id), ("superseded", "=", False)])

    def _run_submit(self):
        self.env["authenta.verification"]._cron_submit_pending()

    def _make_due(self, verifications):
        verifications.sudo().write({"next_attempt_at": fields.Datetime.now() - timedelta(seconds=1)})

    def _run_poll(self):
        self._make_due(self.env["authenta.verification"].sudo().search([("state", "in", ("submitted", "processing"))]))
        self.env["authenta.verification"]._cron_poll()

    def _sheet(self, expenses):
        sheet = self.env["hr.expense.sheet"].create({
            "name": "Report",
            "employee_id": expenses[0].employee_id.id,
            "expense_line_ids": [(6, 0, expenses.ids)],
        })
        sheet.action_submit_sheet()
        return sheet

    def _complete_all(self, verdicts):
        """verdicts: {attachment: result dict}"""
        for attachment, result in verdicts.items():
            self.client.complete(self._verification(attachment).authenta_job_id, result)
        self._run_poll()

    # ---------------------------------------------------------------- submission

    def test_receipt_creates_pending_verification_automatically(self):
        expense = self._expense()
        attachment = self._attach(expense)

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "pending")
        self.assertEqual(expense.authenta_status, "processing")
        self.assertFalse(self.client.create_calls, "No HTTP call may happen in the employee request")

    def test_no_verification_when_disabled(self):
        self.env["ir.config_parameter"].sudo().set_param("authenta_expense.enabled", False)
        attachment = self._attach(self._expense())

        self.assertFalse(self._verification(attachment))

    def test_png_is_submitted_to_document_intelligence(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()

        verification = self._verification(attachment)
        call = self.client.create_calls[0]
        self.assertEqual(verification.state, "submitted")
        self.assertEqual(call["task_type_id"], "6")
        self.assertEqual(call["content_type"], "image/png")
        self.assertEqual(call["size_bytes"], len(PNG_1X1))
        self.assertIsNone(call["page_count"])
        self.assertEqual(call["external_reference"], verification.external_reference)
        self.assertIn(f":attachment:{attachment.id}", call["external_reference"])
        self.assertEqual(call["external_metadata"]["expenseId"], str(expense.id))
        self.assertEqual(self.client.uploads[0][2], "image/png")
        self.assertEqual(self.client.finalized, [verification.authenta_job_id])

    def test_jpeg_is_submitted_to_document_intelligence(self):
        attachment = self._attach(self._expense(), name="receipt.jpg", mimetype="image/jpeg")
        self._run_submit()

        self.assertEqual(self.client.create_calls[0]["task_type_id"], "6")
        self.assertEqual(self._verification(attachment).state, "submitted")

    def test_pdf_is_submitted_with_its_page_count(self):
        attachment = self._attach(self._expense(), name="receipt.pdf", data=make_pdf(2), mimetype="application/pdf")
        self._run_submit()

        call = self.client.create_calls[0]
        self.assertEqual(call["task_type_id"], "12")
        self.assertEqual(call["page_count"], 2)
        self.assertEqual(self._verification(attachment).state, "submitted")

    def test_invalid_pdf_is_a_verification_error(self):
        attachment = self._attach(self._expense(), name="receipt.pdf", data=b"%PDF-broken", mimetype="application/pdf")
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "error")
        self.assertIn("could not be read", verification.last_error)
        self.assertFalse(self.client.create_calls)

    def test_unsupported_type_is_a_verification_error(self):
        expense = self._expense()
        attachment = self._attach(expense, name="notes.txt", data=b"hello", mimetype="text/plain")
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "error")
        self.assertIn("not supported", verification.last_error)
        self.assertEqual(expense.authenta_status, "error")
        self.assertFalse(self.client.create_calls)

    def test_oversized_receipt_is_a_verification_error(self):
        self.env["ir.config_parameter"].sudo().set_param("authenta_expense.max_file_size_mb", 1)
        attachment = self._attach(self._expense(), data=PNG_1X1 + b"0" * (1024 * 1024 + 1))
        self._run_submit()

        self.assertEqual(self._verification(attachment).state, "error")
        self.assertFalse(self.client.create_calls)

    def test_idempotency_key_is_stable_across_retries(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["create_job"] = AuthentaTransientError("Authenta returned HTTP 503", 503)
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "pending")
        self.assertEqual(verification.attempts, 1)
        self.assertGreater(verification.next_attempt_at, fields.Datetime.now())

        self._make_due(verification)
        self._run_submit()
        keys = {call["idempotency_key"] for call in self.client.create_calls}
        self.assertEqual(len(self.client.create_calls), 2)
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(self.client.jobs), 1)
        self.assertEqual(verification.state, "submitted")

    def test_network_error_retries_with_backoff(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["create_job"] = AuthentaTransientError("Could not reach Authenta (ConnectionError)")
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "pending")
        self.assertIn("Could not reach", verification.last_error)

    def test_expired_upload_url_is_retried_with_a_fresh_url(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["upload_file"] = AuthentaUploadError("Receipt upload was rejected (HTTP 403)", 403)
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "pending")
        self._make_due(verification)
        self._run_submit()

        self.assertEqual(verification.state, "submitted")
        self.assertEqual(len(self.client.jobs), 1)
        self.assertEqual(len(self.client.uploads), 1)
        self.assertTrue(self.client.uploads[0][0].endswith("/2"), "The retry must use the fresh upload URL")

    def test_transient_errors_are_bounded(self):
        attachment = self._attach(self._expense())
        verification = self._verification(attachment)
        for _attempt in range(MAX_TRANSIENT_ATTEMPTS):
            self.client.fail_next["create_job"] = AuthentaTransientError("Timed out calling Authenta POST /jobs")
            self._make_due(verification)
            self._run_submit()

        self.assertEqual(verification.state, "error")
        self.assertIn("gave up", verification.last_error)

    def test_insufficient_balance_is_not_retried(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["create_job"] = AuthentaBillingError("Insufficient balance", 402, "INSUFFICIENT_BALANCE")
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "error")
        self.assertIn("insufficient credits", verification.last_error)
        self.assertFalse(verification.next_attempt_at)

    def test_invalid_credentials_mark_receipts_as_configuration_errors(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["test_connection"] = AuthentaAuthError("API key authentication failed", 401, "INVALID_API_KEY")
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "error")
        self.assertIn("rejected the integration API key", verification.last_error)

    def test_authenta_unreachable_postpones_submission(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["test_connection"] = AuthentaTransientError("Could not reach Authenta")
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "pending")
        self.assertEqual(verification.attempts, 0)

    # ---------------------------------------------------------------- polling & results

    def test_polling_moves_through_processing_to_completed_real(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        verification = self._verification(attachment)

        self._run_poll()
        self.assertEqual(verification.state, "processing")

        self._complete_all({attachment: {"isFake": False, "isTampered": False, "confidence": 0.05}})
        self.assertEqual(verification.state, "completed")
        self.assertEqual(verification.verdict, "real")
        self.assertIn('"isTampered": false', verification.result)
        self.assertEqual(expense.authenta_status, "real")

    def test_completed_records_are_not_polled_again(self):
        attachment = self._attach(self._expense())
        self._run_submit()
        self._complete_all({attachment: {"isFake": False, "isTampered": False}})

        with patch.object(FakeAuthentaClient, "get_job", side_effect=AssertionError("must not poll")):
            self.env["authenta.verification"]._cron_poll()

    def test_failed_job_is_not_treated_as_fake(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self.client.jobs[self._verification(attachment).authenta_job_id]["status"] = "failed"
        self._run_poll()

        verification = self._verification(attachment)
        self.assertEqual(verification.state, "failed")
        self.assertEqual(verification.verdict, "unknown")
        self.assertEqual(expense.authenta_status, "error")

    def test_worker_error_result_is_unknown_not_real(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self._complete_all({attachment: {"error": "OutOfMemoryError", "message": "boom"}})

        self.assertEqual(self._verification(attachment).verdict, "unknown")
        self.assertEqual(expense.authenta_status, "error")

    def test_real_and_real_is_real(self):
        expense = self._expense()
        first, second = self._attach(expense, "a.png"), self._attach(expense, "b.png")
        self._run_submit()
        self._complete_all({first: {"isFake": False, "isTampered": False}, second: {"isFake": False, "isTampered": False}})

        self.assertEqual(expense.authenta_status, "real")

    def test_real_and_fake_is_fake(self):
        expense = self._expense()
        first, second = self._attach(expense, "a.png"), self._attach(expense, "b.png")
        self._run_submit()
        self._complete_all({first: {"isFake": False, "isTampered": False}, second: {"isFake": False, "isTampered": True}})

        self.assertEqual(expense.authenta_status, "fake")
        self.assertIn("b.png", expense.authenta_status_message)

    def test_fake_and_fake_is_fake(self):
        expense = self._expense()
        first, second = self._attach(expense, "a.png"), self._attach(expense, "b.png")
        self._run_submit()
        self._complete_all({first: {"isFake": True, "isTampered": False}, second: {"isFake": True, "isTampered": True}})

        self.assertEqual(expense.authenta_status, "fake")

    # ---------------------------------------------------------------- approval gating

    def test_all_real_allows_approval(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self._complete_all({attachment: {"isFake": False, "isTampered": False}})
        sheet = self._sheet(expense)

        sheet.with_user(self.manager_user).action_approve_expense_sheets()
        self.assertEqual(sheet.state, "approve")

    def test_any_fake_blocks_approval(self):
        expense = self._expense()
        first, second = self._attach(expense, "a.png"), self._attach(expense, "b.png")
        self._run_submit()
        self._complete_all({first: {"isFake": False, "isTampered": False}, second: {"isFake": True, "isTampered": False}})
        sheet = self._sheet(expense)

        with self.assertRaisesRegex(UserError, "FAKE"):
            sheet.with_user(self.manager_user).action_approve_expense_sheets()
        self.assertEqual(sheet.state, "submit")

    def test_pending_blocks_approval(self):
        expense = self._expense()
        self._attach(expense)
        sheet = self._sheet(expense)

        with self.assertRaisesRegex(UserError, "in progress"):
            sheet.with_user(self.manager_user).action_approve_expense_sheets()

    def test_error_blocks_approval(self):
        expense = self._expense()
        self._attach(expense, name="notes.txt", data=b"hello", mimetype="text/plain")
        self._run_submit()
        sheet = self._sheet(expense)

        with self.assertRaisesRegex(UserError, "could not be verified"):
            sheet.with_user(self.manager_user).action_approve_expense_sheets()

    def test_direct_do_approve_is_also_blocked(self):
        expense = self._expense()
        self._attach(expense)
        sheet = self._sheet(expense)

        with self.assertRaises(UserError):
            sheet._do_approve()

    def test_refusing_a_fake_expense_is_still_possible(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self._complete_all({attachment: {"isFake": True, "isTampered": False}})
        sheet = self._sheet(expense)

        sheet.with_user(self.manager_user)._do_refuse("Fake receipt")
        self.assertEqual(sheet.state, "cancel")

    def test_expense_without_receipt_is_not_blocked(self):
        expense = self._expense()
        sheet = self._sheet(expense)

        sheet.with_user(self.manager_user).action_approve_expense_sheets()
        self.assertEqual(sheet.state, "approve")

    # ---------------------------------------------------------------- manager actions

    def test_reverify_creates_a_new_attempt_with_a_new_key(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self._complete_all({attachment: {"isFake": True, "isTampered": False}})
        old = self._verification(attachment)

        old.with_user(self.manager_user).action_reverify()
        new = self._verification(attachment)
        self.assertTrue(old.superseded)
        self.assertNotEqual(new, old)
        self.assertEqual(new.attempt, 2)
        self.assertEqual(expense.authenta_status, "processing")

        self._run_submit()
        self.assertNotEqual(new.idempotency_key, old.idempotency_key)
        self.assertEqual(len(self.client.jobs), 2)

    def test_retry_keeps_the_same_key(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["create_job"] = AuthentaBillingError("Insufficient balance", 402)
        self._run_submit()
        verification = self._verification(attachment)
        key = verification.idempotency_key

        verification.with_user(self.manager_user).action_retry()
        self._run_submit()
        self.assertEqual(verification.state, "submitted")
        self.assertEqual(verification.idempotency_key, key)

    def test_employee_cannot_trigger_manager_actions(self):
        attachment = self._attach(self._expense())
        verification = self._verification(attachment).with_user(self.employee_user)

        with self.assertRaises(UserError):
            verification.action_reverify()

    # ---------------------------------------------------------------- security

    def test_employee_sees_only_own_verifications(self):
        own = self._attach(self._expense())
        other = self._attach(self._expense(employee=self.other_employee))
        Verification = self.env["authenta.verification"].with_user(self.employee_user)

        visible = Verification.search([])
        self.assertIn(self._verification(own), visible.sudo())
        self.assertNotIn(self._verification(other), visible.sudo())
        with self.assertRaises(AccessError):
            self._verification(other).with_user(self.employee_user).read(["state"])

    def test_employee_cannot_read_authenta_credentials(self):
        with self.assertRaises(AccessError):
            self.env["ir.config_parameter"].with_user(self.employee_user).get_param("authenta_expense.api_key")
        with self.assertRaises(AccessError):
            self._verification(self._attach(self._expense())).with_user(self.employee_user).read(["idempotency_key"])

    def test_manager_cannot_write_a_verdict_directly(self):
        attachment = self._attach(self._expense())
        self._run_submit()
        self._complete_all({attachment: {"isFake": True, "isTampered": False}})
        verification = self._verification(attachment)

        with self.assertRaises(AccessError):
            verification.with_user(self.manager_user).write({"verdict": "real"})
        self.assertEqual(verification.verdict, "fake")

    def test_writing_the_expense_status_does_not_bypass_approval(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self._complete_all({attachment: {"isFake": True, "isTampered": False}})
        sheet = self._sheet(expense)

        expense.with_user(self.manager_user).write({"authenta_status": "real", "authenta_status_message": "ok"})
        self.assertEqual(expense.authenta_status, "fake")
        # Even a value forced into the database is ignored: approval re-checks the verifications themselves.
        self.env.cr.execute("UPDATE hr_expense SET authenta_status = 'real' WHERE id = %s", (expense.id,))
        expense.invalidate_recordset()
        with self.assertRaisesRegex(UserError, "FAKE"):
            sheet.with_user(self.manager_user).action_approve_expense_sheets()

    def test_pending_expense_forced_to_real_is_still_blocked(self):
        expense = self._expense()
        self._attach(expense)
        sheet = self._sheet(expense)
        self.env.cr.execute("UPDATE hr_expense SET authenta_status = 'real' WHERE id = %s", (expense.id,))
        expense.invalidate_recordset()

        with self.assertRaisesRegex(UserError, "in progress"):
            sheet.with_user(self.manager_user).action_approve_expense_sheets()

    def test_failed_verification_blocks_approval(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self._run_submit()
        self.client.jobs[self._verification(attachment).authenta_job_id]["status"] = "failed"
        self._run_poll()
        sheet = self._sheet(expense)

        with self.assertRaisesRegex(UserError, "could not be verified"):
            sheet.with_user(self.manager_user).action_approve_expense_sheets()

    def test_lock_skips_records_that_are_no_longer_due(self):
        attachment = self._attach(self._expense())
        verification = self._verification(attachment)

        self.assertTrue(verification._lock_due(("pending",)))
        verification.write({"next_attempt_at": fields.Datetime.now() + timedelta(hours=1)})
        self.assertFalse(verification._lock_due(("pending",)))
        verification.write({"state": "submitted", "next_attempt_at": False})
        self.assertFalse(verification._lock_due(("pending",)))

    def test_a_record_processed_by_another_worker_is_not_submitted_again(self):
        attachment = self._attach(self._expense())
        verification = self._verification(attachment)
        original = type(verification)._lock_due

        def lock_after_other_worker(record, states):
            # Another worker finished this record between this worker's search and its lock.
            record.sudo().write({"state": "submitted"})
            return original(record, states)

        with patch.object(type(verification), "_lock_due", lock_after_other_worker):
            self._run_submit()
        self.assertFalse(self.client.create_calls)

    def test_deleted_receipt_no_longer_counts(self):
        expense = self._expense()
        attachment = self._attach(expense)
        self.assertEqual(expense.authenta_status, "processing")

        attachment.unlink()
        self._run_submit()

        self.assertEqual(expense.authenta_status, "none")
        self.assertFalse(self.client.create_calls)

    def test_receipt_moved_to_another_expense_keeps_its_single_verification(self):
        first, second = self._expense(name="First"), self._expense(name="Second")
        attachment = self._attach(first)
        self._run_submit()

        attachment.write({"res_id": second.id})
        self._run_submit()

        verification = self._verification(attachment)
        self.assertEqual(len(verification), 1)
        self.assertEqual(verification.expense_id, second)
        self.assertEqual(first.authenta_status, "none")
        self.assertEqual(second.authenta_status, "processing")
        self.assertEqual(len(self.client.create_calls), 1)

    def test_submission_logs_contain_no_receipt_data_or_upload_urls(self):
        attachment = self._attach(self._expense())
        self.client.fail_next["upload_file"] = AuthentaUploadError("Receipt upload was rejected (HTTP 403)", 403)
        # A normal submission (with a retryable upload failure) writes nothing to the log: no URL, no file content.
        with self.assertNoLogs("odoo.addons.authenta_expense", level="DEBUG"):
            self._run_submit()
        self.assertEqual(self._verification(attachment).state, "pending")

    def test_connection_check_reports_problems(self):
        settings = self.env["res.config.settings"]
        ok, message = settings._authenta_describe_connection(self.client.test_connection())
        self.assertTrue(ok)
        self.assertIn("Acme", message)

        broken = dict(self.client.test_connection(), permissionNames=["ReadJob"])
        ok, message = settings._authenta_describe_connection(broken)
        self.assertFalse(ok)
        self.assertIn("WriteJob", message)
