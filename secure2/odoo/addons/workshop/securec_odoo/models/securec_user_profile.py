from odoo import models, fields, api
from odoo.exceptions import ValidationError


class SecureCUserProfile(models.Model):
    _name = 'securec.user.profile'
    _description = 'SecureC Behavioral User Profile'
    _order = 'anomaly_score desc'
    _rec_name = 'user_id'

    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True,
        ondelete='cascade',
        index=True,
    )
    total_actions = fields.Integer(
        string='Total Actions',
        default=0,
        help='Cumulative count of actions tracked by the WAF for this user',
    )
    blocked_count = fields.Integer(
        string='Blocked Actions',
        default=0,
        help='Number of actions blocked by the WAF',
    )
    warned_count = fields.Integer(
        string='Warned Actions',
        default=0,
    )
    anomaly_score = fields.Float(
        string='Anomaly Score',
        digits=(4, 3),
        default=0.0,
        help='Rolling anomaly score (0–1). High values indicate insider threat.',
    )
    last_activity = fields.Datetime(
        string='Last Activity',
        default=fields.Datetime.now,
        index=True,
    )
    risk_level = fields.Selection([
        ('low',    'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high',   'High Risk'),
    ], string='Risk Level', compute='_compute_risk_level', store=True, index=True)

    baseline_actions_per_hour = fields.Float(
        string='Baseline Actions/Hour',
        digits=(6, 2),
        default=0.0,
        help='Rolling average of normal actions per hour for this user',
    )
    most_active_module = fields.Char(
        string='Most Active Module',
        help='Module where this user has the highest number of flagged events',
    )
    last_event_id = fields.Many2one(
        'securec.event',
        string='Last Security Event',
        ondelete='set null',
    )
    notes = fields.Text(string='Security Notes')
    color = fields.Integer(string='Color', compute='_compute_color', store=False)

    _sql_constraints = [
        ('user_unique', 'UNIQUE(user_id)', 'A behavioral profile already exists for this user.'),
    ]

    # ── Computed ──────────────────────────────────────────────────────────
    @api.depends('anomaly_score')
    def _compute_risk_level(self):
        for rec in self:
            if rec.anomaly_score >= 0.70:
                rec.risk_level = 'high'
            elif rec.anomaly_score >= 0.30:
                rec.risk_level = 'medium'
            else:
                rec.risk_level = 'low'

    def _compute_color(self):
        _map = {'high': 1, 'medium': 3, 'low': 10}
        for rec in self:
            rec.color = _map.get(rec.risk_level, 10)

    # ── Business Logic ────────────────────────────────────────────────────
    def increment_action(self, decision: str, risk_score: float, module: str = None, event_id: int = None):
        """
        Record a new WAF event for this user.
        - Increments action counters.
        - Updates the anomaly score using a simple exponential moving average.
        - Updates the most active module.
        """
        self.ensure_one()
        self.total_actions += 1
        if decision == 'block':
            self.blocked_count += 1
        elif decision in ('warn', 'sanitize'):
            self.warned_count += 1

        # Exponential moving average on anomaly_score (alpha=0.2)
        alpha = 0.20
        self.anomaly_score = round(
            alpha * risk_score + (1 - alpha) * self.anomaly_score, 3
        )
        self.last_activity = fields.Datetime.now()

        if module:
            self.most_active_module = module

        if event_id:
            self.last_event_id = event_id

    @api.model
    def get_or_create_profile(self, user_id: int):
        """Return (or create) the profile for a user — safe for concurrent calls."""
        profile = self.sudo().search([('user_id', '=', user_id)], limit=1)
        if not profile:
            profile = self.sudo().create({'user_id': user_id})
        return profile

    @api.model
    def high_risk_users(self):
        return self.search([('risk_level', '=', 'high')], order='anomaly_score desc')
