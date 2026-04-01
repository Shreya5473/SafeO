from odoo import models, fields, api


class SecureCAttackSimulation(models.Model):
    _name = 'securec.attack.simulation'
    _description = 'SecureC Attack Simulation Result'
    _order = 'created_at desc'
    _rec_name = 'category'

    event_id = fields.Many2one(
        'securec.event',
        string='Security Event',
        ondelete='cascade',
        index=True,
    )
    payload = fields.Text(
        string='Attack Payload',
        required=True,
        help='The raw attack string that was tested',
    )
    payload_preview = fields.Char(
        string='Payload Preview',
        compute='_compute_payload_preview',
        store=True,
    )
    category = fields.Char(
        string='Attack Category',
        required=True,
        index=True,
        help='e.g. sql_injection, xss, prompt_injection, command_injection',
    )
    result = fields.Selection([
        ('detected', 'Detected ✓'),
        ('missed',   'Missed ✗'),
    ], string='Result', required=True, default='detected', index=True)

    risk_score = fields.Float(
        string='Risk Score',
        digits=(4, 3),
        default=0.0,
    )
    decision = fields.Selection([
        ('allow',    'Allow'),
        ('warn',     'Warn'),
        ('block',    'Block'),
        ('sanitize', 'Sanitize'),
    ], string='Decision', default='allow')
    explanation = fields.Text(string='Explanation')
    created_at = fields.Datetime(
        string='Simulated At',
        default=fields.Datetime.now,
        readonly=True,
        index=True,
    )
    color = fields.Integer(string='Color', compute='_compute_color', store=False)

    # ── Computed ──────────────────────────────────────────────────────────
    @api.depends('payload')
    def _compute_payload_preview(self):
        for rec in self:
            txt = rec.payload or ''
            rec.payload_preview = txt[:80] + ('…' if len(txt) > 80 else '')

    def _compute_color(self):
        for rec in self:
            rec.color = 10 if rec.result == 'detected' else 1

    # ── Class Method: Batch Create from simulation response ───────────────
    @api.model
    def create_from_simulation_response(self, results: list, event_id: int = None):
        """
        Bulk-create simulation records from the FastAPI /simulate/attack response.
        results = list of dicts with keys: attack_type, payload, risk_score, decision, explanation, detected
        """
        vals_list = []
        for r in results:
            vals_list.append({
                'event_id': event_id,
                'payload': r.get('payload', '')[:2000],
                'category': r.get('attack_type', 'unknown'),
                'result': 'detected' if r.get('detected') else 'missed',
                'risk_score': r.get('risk_score', 0.0),
                'decision': r.get('decision', 'allow'),
                'explanation': r.get('explanation', ''),
            })
        return self.sudo().create(vals_list) if vals_list else self.browse()
