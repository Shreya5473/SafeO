import logging
import requests
from odoo import models, fields, api
from odoo.exceptions import UserError
from .securec_language import build_language_payload

_logger = logging.getLogger(__name__)

# Human-readable region names for policy decision messages
REGION_LABELS = {
    'uae': 'UAE',
    'eu': 'EU (GDPR)',
    'us': 'US',
    'global': 'Global',
}

PII_STRICTNESS_LABELS = {
    'low': 'low PII sensitivity',
    'medium': 'medium PII sensitivity',
    'high': 'high PII sensitivity',
    'very_high': 'very high PII sensitivity (GDPR)',
}


class SecureCMixin(models.AbstractModel):
    """
    Abstract Mixin to add SecureC WAF protection to any Odoo model.
    Models inheriting from this should define `_securec_fields_to_check` 
    to specify which text/char fields to scan.
    """
    _name = 'securec.mixin'
    _description = 'SecureC WAF Mixin'

    securec_risk_score = fields.Float('SecureC Risk Score', default=0.0, digits=(3, 3), copy=False)
    securec_decision = fields.Selection([
        ('allow', 'Allow'),
        ('warn', 'Warn'),
        ('block', 'Block'),
        ('sanitize', 'Sanitize'),
    ], string='SecureC Decision', default='allow', copy=False)
    securec_explanation = fields.Text('SecureC Explanation', copy=False)
    securec_flagged = fields.Boolean('Security Flagged', default=False, copy=False)
    securec_log_id = fields.Many2one('securec.log', string='Security Log Entry', copy=False)

    # Models should override this to list fields to inspect
    @property
    def _securec_fields_to_check(self):
        return []

    # Models can override this to specify their module name in the logs
    @property
    def _securec_module_name(self):
        return self._name

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            self._run_waf_check(vals)
        return super().create(vals_list)

    def write(self, vals):
        fields_to_check = self._securec_fields_to_check
        if any(f in vals for f in fields_to_check):
            self._run_waf_check(vals)
        return super().write(vals)

    def _get_active_policy(self):
        params = self.env['ir.config_parameter'].sudo()
        policy_id = int(params.get_param('securec.active_policy_id', 0))
        if policy_id:
            policy = self.env['securec.policy'].sudo().browse(policy_id)
            if policy.exists():
                return policy
        return None

    def _run_waf_check(self, vals):
        fields_to_check = self._securec_fields_to_check
        if not fields_to_check:
            return

        text_parts = [str(vals[f]) for f in fields_to_check if vals.get(f)]
        if not text_parts:
            return

        input_text = ' | '.join(text_parts)
        params = self.env['ir.config_parameter'].sudo()
        api_url = params.get_param('securec.api_url', 'http://localhost:8001')

        # Policy and Thresholds
        policy = self._get_active_policy()
        block_threshold = policy.block_threshold if policy else float(params.get_param('securec.block_threshold', '0.70'))
        warn_threshold = float(params.get_param('securec.warn_threshold', '0.30'))

        # Language payload
        lang_payload = build_language_payload(input_text)
        language = lang_payload['language']
        normalized = lang_payload['normalized_input']

        # API Request
        module_name = self._securec_module_name
        api_payload = {
            "input_text": input_text,
            "normalized_input": normalized,
            "language": language,
            "user_id": str(self.env.user.id),
            "module": module_name,
        }
        if policy:
            api_payload["region"] = policy.region
            api_payload["policy"] = policy.get_policy_dict()

        try:
            resp = requests.post(f"{api_url}/waf/input", json=api_payload, timeout=5)
            if resp.status_code != 200:
                _logger.warning(f"SecureC API returned {resp.status_code}")
                return

            data = resp.json()
            risk_score = data.get('risk_score', 0.0)
            decision = data.get('decision', 'allow')
            explanation = data.get('explanation', '')
            patterns = data.get('detected_patterns', [])
            sanitized = data.get('sanitized_text')

            policy_decision_reason = ''
            if policy:
                region_label = REGION_LABELS.get(policy.region, policy.region.upper())
                pii_label = PII_STRICTNESS_LABELS.get(policy.pii_strictness, policy.pii_strictness)

                if risk_score > policy.block_threshold and decision != 'block':
                    decision = 'block'
                    policy_decision_reason = f"Forced BLOCK by {region_label} policy: {pii_label} (threshold {policy.block_threshold:.0%})"
                elif decision == 'block':
                    policy_decision_reason = f"Blocked due to {region_label} policy: {pii_label}"

                if policy.masking_enabled and sanitized:
                    decision = 'sanitize'
                    policy_decision_reason += f" | PII masking active ({region_label})"

                if lang_payload.get('has_threat_signals'):
                    policy_decision_reason += f" | Multilingual threat signal detected [{language.upper()}]"
            else:
                if risk_score >= block_threshold:
                    decision = 'block'

            # Update Vals
            vals['securec_risk_score'] = risk_score
            vals['securec_decision'] = decision
            vals['securec_explanation'] = explanation
            vals['securec_flagged'] = risk_score >= warn_threshold

            # Audit Log
            log_vals = {
                'input_text': input_text[:1000],
                'risk_score': risk_score,
                'decision': decision,
                'explanation': explanation,
                'detected_patterns': ', '.join(patterns),
                'sanitized_text': sanitized,
                'user_id': self.env.user.id,
                'module': module_name,
                'detected_language': language,
                'normalized_text': normalized if normalized != input_text else False,
                'policy_id': policy.id if policy else False,
                'policy_region': policy.region if policy else False,
                'policy_decision_reason': policy_decision_reason or False,
            }
            log = self.env['securec.log'].sudo().create(log_vals)
            vals['securec_log_id'] = log.id

            # Behavior Tracking
            try:
                requests.post(
                    f"{api_url}/waf/behavior",
                    json={"user_id": str(self.env.user.id), "action": f"{module_name}_save", "module": module_name},
                    timeout=2,
                )
            except Exception:
                pass

            if decision == 'block':
                lang_info = f"[{language.upper()}]" if language != 'en' else ''
                raise UserError(
                    f"🛡️ SecureC blocked this input {lang_info}\n\n"
                    f"Risk Score: {risk_score:.0%}  |  Decision: {decision.upper()}\n\n"
                    f"Reason: {explanation}\n\n"
                    f"Detected patterns: {', '.join(patterns) or 'N/A'}\n\n"
                    + (f"Policy: {policy_decision_reason}\n\n" if policy_decision_reason else "")
                    + "Please remove the flagged content and try again.\n"
                    + (f"\nSuggested safe version:\n{sanitized}" if sanitized else "")
                )

        except UserError:
            raise
        except Exception as e:
            _logger.warning(f"SecureC WAF check failed: {e}")
