from odoo import _, api, fields, models
from odoo.exceptions import UserError

from ..services.receipt_logic import overall_status

AUTHENTA_STATUS_SELECTION = [
    ("none", "No Receipt"),
    ("processing", "Verifying"),
    ("real", "Verified"),
    ("fake", "Fake Receipt"),
    ("error", "Not Verified"),
]

BLOCKING_STATUSES = ("processing", "fake", "error")
# Computed from the verifications only; never accepted from a client write.
PROTECTED_FIELDS = ("authenta_status", "authenta_status_message")


class HrExpense(models.Model):
    _inherit = "hr.expense"

    authenta_verification_ids = fields.One2many("authenta.verification", "expense_id", string="Receipt Verifications")
    authenta_status = fields.Selection(
        selection=AUTHENTA_STATUS_SELECTION,
        string="Receipt Verification",
        compute="_compute_authenta_status",
        store=True,
        default="none",
        help="Overall Authenta result for this expense's receipts: any fake receipt makes the expense fake; "
        "it is verified only when every receipt is verified as real.",
    )
    authenta_status_message = fields.Char(string="Verification Details", compute="_compute_authenta_status", store=True)

    @api.depends(
        "authenta_verification_ids.state",
        "authenta_verification_ids.verdict",
        "authenta_verification_ids.superseded",
        "authenta_verification_ids.attachment_id",
    )
    def _compute_authenta_status(self):
        for expense in self:
            status, current = expense._authenta_live_status()
            expense.authenta_status = status
            expense.authenta_status_message = expense._authenta_status_message(status, current)

    def _authenta_live_status(self):
        """Returns (status, current verifications), computed from the verification records themselves."""
        self.ensure_one()
        current = self.sudo().authenta_verification_ids.filtered(lambda v: not v.superseded and v.attachment_id)
        return overall_status((v.state, v.verdict) for v in current), current

    def write(self, vals):
        if any(field in vals for field in PROTECTED_FIELDS):
            vals = {key: value for key, value in vals.items() if key not in PROTECTED_FIELDS}
        return super().write(vals)

    def _authenta_status_message(self, status, verifications):
        if status == "fake":
            names = ", ".join(v.attachment_name for v in verifications if v.state == "completed" and v.verdict == "fake")
            return _("Receipt flagged as fake: %s", names)
        if status == "error":
            reasons = {v.last_error for v in verifications if v.state in ("error", "failed") and v.last_error}
            return _("Receipt could not be verified: %s", "; ".join(sorted(reasons)) or _("inconclusive result"))
        if status == "processing":
            return _("Receipt verification in progress")
        if status == "real":
            return _("All receipts verified")
        return False


class HrExpenseSheet(models.Model):
    _inherit = "hr.expense.sheet"

    authenta_status = fields.Selection(
        selection=AUTHENTA_STATUS_SELECTION,
        string="Receipt Verification",
        compute="_compute_authenta_status",
    )

    @api.depends("expense_line_ids.authenta_status")
    def _compute_authenta_status(self):
        for sheet in self:
            statuses = set(sheet.expense_line_ids.mapped("authenta_status"))
            if "fake" in statuses:
                sheet.authenta_status = "fake"
            elif "error" in statuses:
                sheet.authenta_status = "error"
            elif "processing" in statuses:
                sheet.authenta_status = "processing"
            elif "real" in statuses:
                sheet.authenta_status = "real"
            else:
                sheet.authenta_status = "none"

    def _authenta_check_approval(self):
        """Blocks approval while any receipt is fake, still being verified, or could not be verified."""
        if not self.env["authenta.verification"]._is_enabled():
            return
        problems = []
        for sheet in self:
            for expense in sheet.expense_line_ids:
                # Recomputed from the verification records: the stored status is only for display.
                status, current = expense._authenta_live_status()
                if status not in BLOCKING_STATUSES:
                    continue
                if status == "fake":
                    reason = _("a receipt was flagged as FAKE by Authenta")
                elif status == "processing":
                    reason = _("receipt verification is still in progress")
                else:
                    detail = expense._authenta_status_message(status, current)
                    reason = _("a receipt could not be verified (%s)", detail or _("unknown error"))
                problems.append(_("%(sheet)s / %(expense)s: %(reason)s", sheet=sheet.name, expense=expense.name, reason=reason))
        if problems:
            raise UserError(_("You cannot approve these expenses:\n%s", "\n".join(problems)))

    def _check_can_approve(self):
        super()._check_can_approve()
        self._authenta_check_approval()

    def _do_approve(self):
        # Also covers flows that approve without _check_can_approve (e.g. the duplicate-expense wizard).
        self._authenta_check_approval()
        return super()._do_approve()

    def _check_can_create_move(self):
        # Receipts added after approval must not be paid out while fake or unverified.
        super()._check_can_create_move()
        self._authenta_check_approval()
