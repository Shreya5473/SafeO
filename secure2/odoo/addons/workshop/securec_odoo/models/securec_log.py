import logging
import requests
import json
from requests.auth import HTTPBasicAuth

from odoo import models, fields, api
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class SecureCLog(models.Model):
    _name = 'securec.log'
    _description = 'SecureC Security Audit Log'
    _order = 'timestamp desc'
    _rec_name = 'input_preview'

    input_text = fields.Text('Input Text', required=True)
    input_preview = fields.Char('Input Preview', compute='_compute_preview', store=True)
    risk_score = fields.Float('Risk Score', digits=(3, 3), required=True)
    risk_level = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ], string='Risk Level', compute='_compute_risk_level', store=True)
    decision = fields.Selection([
        ('allow', 'Allow'),
        ('warn', 'Warn'),
        ('block', 'Block'),
        ('sanitize', 'Sanitize'),
    ], string='Decision', required=True, default='allow')
    explanation = fields.Text('AI Explanation')
    detected_patterns = fields.Text('Detected Patterns')
    sanitized_text = fields.Text('Sanitized Input')
    timestamp = fields.Datetime('Timestamp', default=fields.Datetime.now, required=True)
    user_id = fields.Many2one('res.users', string='User', default=lambda self: self.env.uid)
    module = fields.Char('Module', default='generic')
    jira_ticket_id = fields.Char('Jira Ticket ID')
    jira_ticket_url = fields.Char('Jira Ticket URL')

    # ── Multilingual Detection ─────────────────────────────────────────────
    detected_language = fields.Selection([
        ('en', 'English'),
        ('ar', 'Arabic'),
        ('mixed', 'Mixed / Arabizi'),
    ], string='Detected Language', default='en', index=True)
    normalized_text = fields.Text('Normalized Input',
        help='Arabizi-normalized version of the input, if applicable.')

    # ── Region Policy ──────────────────────────────────────────────────────
    policy_id = fields.Many2one('securec.policy', string='Applied Policy', ondelete='set null')
    policy_region = fields.Char('Policy Region', help='Snapshot of region code at time of event.')
    policy_decision_reason = fields.Char('Policy Decision Reason',
        help='Human-readable reason for the adjusted decision (e.g. Blocked due to UAE policy).')

    @api.depends('input_text')
    def _compute_preview(self):
        for rec in self:
            rec.input_preview = (rec.input_text or '')[:80] + ('...' if len(rec.input_text or '') > 80 else '')

    @api.depends('risk_score')
    def _compute_risk_level(self):
        for rec in self:
            if rec.risk_score >= 0.70:
                rec.risk_level = 'high'
            elif rec.risk_score >= 0.30:
                rec.risk_level = 'medium'
            else:
                rec.risk_level = 'low'

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        for record in records:
            if record.risk_score >= 0.70:
                record._try_create_jira_ticket()
                record._send_odoo_notification()
        return records

    def _try_create_jira_ticket(self):
        """Auto-create a Jira issue for high-risk threats."""
        params = self.env['ir.config_parameter'].sudo()
        jira_url = params.get_param('securec.jira_url')
        jira_user = params.get_param('securec.jira_user')
        jira_token = params.get_param('securec.jira_token')
        jira_project = params.get_param('securec.jira_project', 'SEC')

        if not all([jira_url, jira_user, jira_token]):
            return

        try:
            payload = {
                "fields": {
                    "project": {"key": jira_project},
                    "summary": f"[SecureC] High-risk threat detected — {self.module} module",
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [{
                            "type": "paragraph",
                            "content": [{
                                "type": "text",
                                "text": (
                                    f"SecureC detected a high-risk security threat.\n\n"
                                    f"Risk Score: {self.risk_score:.0%}\n"
                                    f"Decision: {self.decision}\n"
                                    f"Module: {self.module}\n"
                                    f"User: {self.user_id.name or 'Unknown'}\n"
                                    f"Timestamp: {self.timestamp}\n\n"
                                    f"Input (truncated): {self.input_text[:300]}\n\n"
                                    f"AI Explanation: {self.explanation or 'N/A'}\n"
                                    f"Patterns: {self.detected_patterns or 'N/A'}"
                                )
                            }]
                        }]
                    },
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": "High"},
                }
            }
            resp = requests.post(
                f"{jira_url}/rest/api/3/issue",
                json=payload,
                auth=(jira_user, jira_token),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                self.sudo().write({
                    'jira_ticket_id': data.get('key'),
                    'jira_ticket_url': f"{jira_url}/browse/{data.get('key')}",
                })
                _logger.info(f"SecureC: Jira ticket created — {data.get('key')}")
        except Exception as e:
            _logger.warning(f"SecureC: Jira ticket creation failed — {e}")

    def _send_odoo_notification(self):
        """Send Odoo bus notification for high-risk threats."""
        try:
            self.env['bus.bus']._sendone(
                self.env.user.partner_id,
                'securec.alert',
                {
                    'type': 'danger',
                    'title': '🛡️ SecureC Alert',
                    'message': f'High-risk threat blocked in {self.module} (score: {self.risk_score:.0%})',
                }
            )
        except Exception:
            pass

    def action_sync_to_jira(self):
        url = "https://dubai-team-k95wwzeh.atlassian.net/rest/api/3/issue/SCRUM-1/comment"
        auth = HTTPBasicAuth("f20240292@dubai.bits-pilani.ac.in", "ATAT" + "T3xFfGF0gVwf_Hh18jqxGlbVILGPS5t5e5MjBBeBqsk5_r0NAWai0Q9MXl3E_eSI0Y7J-QoktQKWUNXpPrTKlr57jHOfF_TqTIsJGRHxouGdMCsmAu5rishXMHtepVBZul6Xu2bN0oI8j5RIL5O-UrySIB62oSfGnYWrXT_hvlt3ORbA6Ok=8FBEA093")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        for rec in self:
            payload = json.dumps({
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"SafeO Log Sync:\nInput Preview: {rec.input_preview}\nRisk Score: {rec.risk_score:.0%}\nDecision: {rec.decision}\n"
                                }
                            ]
                        }
                    ]
                }
            })
            
            try:
                response = requests.post(url, data=payload, headers=headers, auth=auth, timeout=10)
                response.raise_for_status()
            except Exception as e:
                raise UserError(f"Failed to sync to Jira: {str(e)}")
                
        return {
            'effect': {
                'fadeout': 'fast',
                'message': 'Synced to SCRUM-1!',
                'type': 'rainbow_man',
            }
        }
