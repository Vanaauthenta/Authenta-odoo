from odoo.tests import TransactionCase, tagged


@tagged("post_install", "-at_install", "authenta")
class TestInstallation(TransactionCase):
    def test_module_and_dependencies_are_installed(self):
        modules = self.env["ir.module.module"].search([("name", "in", ("authenta_expense", "hr_expense"))])
        self.assertEqual(set(modules.mapped("state")), {"installed"})
        self.assertEqual(len(modules), 2)

    def test_security_is_loaded(self):
        access = self.env["ir.model.access"].search([("model_id.model", "=", "authenta.verification")])
        self.assertEqual(len(access), 2)
        self.assertFalse(any(access.mapped("perm_write")), "Verification results are written by the module only")
        self.assertFalse(any(access.mapped("perm_create")))
        self.assertFalse(any(access.mapped("perm_unlink")))
        rules = self.env["ir.rule"].search([("model_id.model", "=", "authenta.verification")])
        self.assertEqual(len(rules), 4)

    def test_background_jobs_are_installed(self):
        for xmlid in ("authenta_expense.ir_cron_authenta_submit", "authenta_expense.ir_cron_authenta_poll"):
            self.assertTrue(self.env.ref(xmlid).active, xmlid)

    def test_verification_is_off_until_an_administrator_opts_in(self):
        # A fresh install sends nothing: the opt-in and the connection are both explicit administrator steps.
        params = self.env["ir.config_parameter"].sudo()
        params.set_param("authenta_expense.enabled", False)
        params.set_param("authenta_expense.api_key", False)
        self.assertFalse(self.env["authenta.verification"]._is_active())
