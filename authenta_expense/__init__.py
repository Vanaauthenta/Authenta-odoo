from . import services
from . import models
from . import controllers


def uninstall_hook(env):
    """Removes the Authenta credential and settings; the Authenta-side integration stays until disabled in Authenta."""
    env["ir.config_parameter"].sudo().search([("key", "=like", "authenta_expense.%")]).unlink()
