from odoo import api, models


class IrAttachment(models.Model):
    _inherit = "ir.attachment"

    @api.model_create_multi
    def create(self, vals_list):
        attachments = super().create(vals_list)
        self.env["authenta.verification"]._create_for_attachments(attachments)
        return attachments

    def write(self, vals):
        result = super().write(vals)
        # Receipts can be linked to an expense after upload (e.g. "create expense from receipt").
        if "res_model" in vals or "res_id" in vals:
            self.env["authenta.verification"]._create_for_attachments(self)
        return result
