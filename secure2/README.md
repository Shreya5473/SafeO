# SecureC — AI WAF for Odoo

This repository contains:

- **`securec_backend/`** — FastAPI service (risk scoring, `/waf/*`, `/simulate/attack`, `/metrics`).
- **`odoo/addons/workshop/securec_odoo/`** — Odoo 19 module (CRM hooks, dashboard, logs, settings).

## Quick start

1. Clone [Odoo](https://github.com/odoo/odoo) and add `odoo/addons/workshop` from this repo into your Odoo `addons-path`, or merge `securec_odoo` into your addons directory.

2. **Backend** (from this repo root so imports resolve)
   ```bash
   python -m venv securec_venv && source securec_venv/bin/activate
   pip install -r securec_backend/requirements.txt
   uvicorn securec_backend.main:app --host 0.0.0.0 --port 8001 --reload
   ```

3. **Odoo** — Install module **SecureC — AI Web Application Firewall**, set **SecureC API URL** to `http://localhost:8001` in Settings.

## License

LGPL-3 (Odoo module per Odoo ecosystem norms). Adjust as needed for your project.
