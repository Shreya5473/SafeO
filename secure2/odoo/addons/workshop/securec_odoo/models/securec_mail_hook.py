"""
securec_mail_hook.py
~~~~~~~~~~~~~~~~~~~~~
Hooks into Odoo's mail.message creation to scan message bodies
for threats before they are persisted.

This extends any message posted in Odoo (chatter, emails, notes)
to be scanned by SecureC's WAF.
"""
import logging
from odoo import models, api

_logger = logging.getLogger(__name__)

# Minimum body length to bother scanning (skip tiny "Assigned to X" notes)
MIN_BODY_LEN = 20


class MailMessage(models.Model):
    _inherit = 'mail.message'

    @api.model_create_multi
    def create(self, vals_list):
        """Scan message bodies before creation. Block if WAF says so."""
        params = self.env['ir.config_parameter'].sudo()
        if params.get_param('securec.enable_mail', 'True') != 'True':
            return super().create(vals_list)

        from ..services import SecureCService
        svc = SecureCService(self.env)

        for vals in vals_list:
            body = vals.get('body') or ''
            # Strip HTML tags for scanning — keep raw text
            import re
            clean_body = re.sub(r'<[^>]+>', ' ', body).strip()

            if len(clean_body) < MIN_BODY_LEN:
                continue

            try:
                response = svc.scan_and_log_input(
                    input_text=clean_body,
                    module='mail',
                    raise_on_block=True,
                )
                # If sanitized, replace the body with the sanitized version
                if response.get('decision') == 'sanitize' and response.get('sanitized_text'):
                    import html
                    vals['body'] = html.escape(response['sanitized_text'])
            except Exception as exc:
                # Re-raise UserError (WAF block), swallow everything else (fail-safe)
                from odoo.exceptions import UserError
                if isinstance(exc, UserError):
                    raise
                _logger.warning("SecureC mail scan failed (safe-pass): %s", exc)

        return super().create(vals_list)
