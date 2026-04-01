import json
import logging
from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class SecureCEvent(models.Model):
    _name = 'securec.event'
    _description = 'SecureC Security Event'
    _order = 'timestamp desc'
    _rec_name = 'name'

    # ── Identity ──────────────────────────────────────────────────────────
    name = fields.Char(
        string='Reference',
        readonly=True,
        copy=False,
        default='New',
        index=True,
    )
    timestamp = fields.Datetime(
        string='Timestamp',
        default=fields.Datetime.now,
        required=True,
        index=True,
    )
    user_id = fields.Many2one(
        'res.users',
        string='User',
        default=lambda self: self.env.user,
        index=True,
        ondelete='set null',
    )

    # ── Classification ────────────────────────────────────────────────────
    module = fields.Selection([
        ('crm',        'CRM'),
        ('hr',         'HR'),
        ('sales',      'Sales'),
        ('purchase',   'Purchase'),
        ('accounting', 'Accounting'),
        ('mail',       'Messaging'),
        ('system',     'System'),
        ('generic',    'Generic'),
    ], string='Module', required=True, default='generic', index=True)

    event_type = fields.Selection([
        ('input',      'Input Scan'),
        ('output',     'Output Scan'),
        ('behavior',   'Behavior Check'),
        ('simulation', 'Attack Simulation'),
    ], string='Event Type', required=True, default='input', index=True)

    # ── Payload ───────────────────────────────────────────────────────────
    input_text = fields.Text(string='Input Text')
    output_text = fields.Text(string='Output Text')
    request_payload = fields.Text(string='Request Payload (JSON)', help='Full JSON payload sent to SecureC API')
    response_payload = fields.Text(string='Response Payload (JSON)', help='Full JSON response from SecureC API')

    # ── Risk Analysis ─────────────────────────────────────────────────────
    risk_score = fields.Float(
        string='Risk Score',
        digits=(4, 3),
        default=0.0,
        help='Normalized 0–1 risk score from SecureC ML engine',
    )
    decision = fields.Selection([
        ('allow',    'Allow'),
        ('warn',     'Warn'),
        ('block',    'Block'),
        ('sanitize', 'Sanitize'),
    ], string='Decision', required=True, default='allow', index=True)
    explanation = fields.Text(string='AI Explanation')
    detected_patterns = fields.Text(string='Detected Patterns')

    # ── Status ────────────────────────────────────────────────────────────
    status = fields.Selection([
        ('success', 'Success'),
        ('failed',  'Failed'),
        ('pending', 'Pending'),
    ], string='Status', default='success', required=True, index=True)

    # ── Relations ─────────────────────────────────────────────────────────
    agent_log_ids = fields.One2many(
        'securec.agent.log', 'event_id', string='Agent Reasoning Logs'
    )
    simulation_id = fields.One2many(
        'securec.attack.simulation', 'event_id', string='Simulation Result'
    )

    # ── Computed / UI ─────────────────────────────────────────────────────
    risk_level = fields.Selection([
        ('low',    'Low'),
        ('medium', 'Medium'),
        ('high',   'High'),
    ], string='Risk Level', compute='_compute_risk_level', store=True, index=True)

    risk_score_pct = fields.Char(
        string='Risk %', compute='_compute_risk_pct', store=False
    )
    agent_count = fields.Integer(
        string='Agents', compute='_compute_agent_count', store=True
    )
    input_preview = fields.Char(
        string='Input Preview', compute='_compute_input_preview', store=True
    )
    color = fields.Integer(string='Color Index', compute='_compute_color', store=False)

    # ── Sequence ──────────────────────────────────────────────────────────
    @api.model_create_multi
    def create(self, vals_list):
        seq = self.env['ir.sequence'].next_by_code('securec.event')
        for vals in vals_list:
            if vals.get('name', 'New') == 'New':
                vals['name'] = seq or 'New'
        return super().create(vals_list)

    # ── Computed Fields ───────────────────────────────────────────────────
    @api.depends('risk_score')
    def _compute_risk_level(self):
        for rec in self:
            if rec.risk_score >= 0.70:
                rec.risk_level = 'high'
            elif rec.risk_score >= 0.30:
                rec.risk_level = 'medium'
            else:
                rec.risk_level = 'low'

    @api.depends('risk_score')
    def _compute_risk_pct(self):
        for rec in self:
            rec.risk_score_pct = f"{round(rec.risk_score * 100)}%"

    @api.depends('agent_log_ids')
    def _compute_agent_count(self):
        for rec in self:
            rec.agent_count = len(rec.agent_log_ids)

    @api.depends('input_text')
    def _compute_input_preview(self):
        for rec in self:
            txt = rec.input_text or ''
            rec.input_preview = txt[:80] + ('…' if len(txt) > 80 else '')

    def _compute_color(self):
        # Odoo list color: 1=red, 2=orange/yellow, 10=dark green
        _map = {'high': 1, 'medium': 3, 'low': 10}
        for rec in self:
            rec.color = _map.get(rec.risk_level, 10)

    # ── Helpers ───────────────────────────────────────────────────────────
    def get_request_payload_dict(self):
        """Safely decode the JSON request payload."""
        self.ensure_one()
        try:
            return json.loads(self.request_payload or '{}')
        except Exception:
            return {}

    def get_response_payload_dict(self):
        """Safely decode the JSON response payload."""
        self.ensure_one()
        try:
            return json.loads(self.response_payload or '{}')
        except Exception:
            return {}

    # ── Dashboard Aggregation Methods ─────────────────────────────────────
    @api.model
    def get_aggregated_stats(self, domain=None):
        """
        Return stats dict suitable for dashboard cards.
        Domain can filter by date, user, module, etc.
        """
        domain = domain or []
        Log = self.search(domain)
        total = len(Log)
        if not total:
            return {
                'total': 0, 'blocked': 0, 'warned': 0, 'allowed': 0,
                'avg_risk': 0.0, 'block_rate': 0.0,
                'by_module': {}, 'by_risk_level': {'low': 0, 'medium': 0, 'high': 0},
                'top_patterns': [],
            }
        blocked = Log.filtered(lambda r: r.decision == 'block')
        warned = Log.filtered(lambda r: r.decision == 'warn')
        avg_risk = sum(Log.mapped('risk_score')) / total

        by_module = {}
        for record in Log:
            mod = record.module or 'generic'
            by_module[mod] = by_module.get(mod, 0) + 1

        by_risk = {
            'low':    len(Log.filtered(lambda r: r.risk_level == 'low')),
            'medium': len(Log.filtered(lambda r: r.risk_level == 'medium')),
            'high':   len(Log.filtered(lambda r: r.risk_level == 'high')),
        }

        return {
            'total': total,
            'blocked': len(blocked),
            'warned': len(warned),
            'allowed': total - len(blocked) - len(warned),
            'avg_risk': round(avg_risk, 3),
            'block_rate': round(len(blocked) / total * 100, 1),
            'by_module': by_module,
            'by_risk_level': by_risk,
        }
