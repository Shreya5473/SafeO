from odoo import models, fields, api


class SecureCAgentLog(models.Model):
    _name = 'securec.agent.log'
    _description = 'SecureC Agent Reasoning Log'
    _order = 'created_at desc'
    _rec_name = 'agent_name'

    event_id = fields.Many2one(
        'securec.event',
        string='Security Event',
        required=True,
        ondelete='cascade',
        index=True,
    )
    agent_name = fields.Char(
        string='Agent Name',
        required=True,
        index=True,
        help='Name of the AI agent that produced this reasoning (e.g. InputShield, OutputGuard)',
    )
    reasoning = fields.Text(
        string='Reasoning',
        help='Full agent explanation of why it flagged or cleared this request',
    )
    confidence = fields.Float(
        string='Confidence',
        digits=(4, 3),
        default=0.0,
        help='Agent confidence in its decision (0–1)',
    )
    weight = fields.Float(
        string='Weight',
        digits=(4, 3),
        default=1.0,
        help='Weight of this agent in the final risk score calculation',
    )
    decision = fields.Selection([
        ('allow',    'Allow'),
        ('warn',     'Warn'),
        ('block',    'Block'),
        ('sanitize', 'Sanitize'),
    ], string='Agent Decision', default='allow')
    detected_patterns = fields.Text(
        string='Detected Patterns',
        help='Comma-separated list of threat patterns this agent detected',
    )
    created_at = fields.Datetime(
        string='Created At',
        default=fields.Datetime.now,
        readonly=True,
    )

    # Related convenience fields for filtering
    event_module = fields.Selection(
        related='event_id.module', string='Module', store=True, readonly=True
    )
    event_user_id = fields.Many2one(
        related='event_id.user_id', string='User', store=True, readonly=True
    )

    # Computed
    confidence_pct = fields.Char(
        string='Confidence %', compute='_compute_confidence_pct', store=False
    )

    @api.depends('confidence')
    def _compute_confidence_pct(self):
        for rec in self:
            rec.confidence_pct = f"{round(rec.confidence * 100)}%"
