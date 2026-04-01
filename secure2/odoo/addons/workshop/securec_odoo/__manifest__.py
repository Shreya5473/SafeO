{
    'name': 'SafeO (SecureC) — AI Web Application Firewall',
    'version': '19.0.2.6.0',
    'category': 'Security',
    'summary': 'SafeO: AI-native WAF with tiered LLM gating, decision cache, multi-region policies, EN/AR/Arabizi',
    'description': """
SafeO (brand) builds on SecureC: an enterprise-grade AI Web Application Firewall natively integrated into Odoo.
Features:
  - Smart Input Firewall with CRM integration
  - Multi-agent ML security engine (InputShield, OutputGuard, BehaviorWatch)
  - Real-time risk scoring (0-1 normalized)
  - Security audit log with explainable AI
  - Attack simulation mode
  - Insider threat detection
  - Self-healing input sanitization
  - Jira ticket auto-creation for high-risk threats
  - Full OWL-based security dashboard
  - Multi-region adaptive compliance policy engine (UAE, EU, US, Global)
  - Multilingual threat detection: English, Arabic, Arabizi
    """,
    'author': 'SecureC',
    'depends': ['base', 'web', 'crm', 'mail', 'website', 'auth_signup'],
    'data': [
        'security/securec_security.xml',
        'security/ir.model.access.csv',
        'data/securec_data.xml',
        'views/securec_policy_views.xml',
        'views/securec_log_views.xml',
        'views/securec_audit_views.xml',
        'views/securec_dashboard_views.xml',
        'views/securec_attack_lab_views.xml',
        'views/crm_lead_views.xml',
        'views/securec_settings_views.xml',
        'views/menu.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'securec_odoo/static/src/css/securec.css',
            'securec_odoo/static/src/xml/securec_dashboard.xml',
            'securec_odoo/static/src/js/dashboard.js',
        ],
    },
    'installable': True,
    'auto_install': False,
    'application': True,
    'license': 'LGPL-3',
}
