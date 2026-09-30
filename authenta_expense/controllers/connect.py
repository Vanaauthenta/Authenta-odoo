from werkzeug.exceptions import Forbidden

from odoo import http
from odoo.http import request

from ..models.res_config_settings import CONNECT_CALLBACK_PATH

# Expenses settings, where the connection status is shown.
SETTINGS_URL = "/web#action=hr_expense.action_hr_expense_configuration"


class AuthentaConnectController(http.Controller):
    @http.route(CONNECT_CALLBACK_PATH, type="http", auth="user", methods=["GET"])
    def authenta_connect_callback(self, **query):
        """Authenta sends the administrator back here after the consent screen; completes the connection and returns to Settings."""
        if not request.env.user.has_group("base.group_system"):
            raise Forbidden()
        request.env["res.config.settings"]._authenta_finish_connection(query)
        return request.redirect(SETTINGS_URL, local=True)
