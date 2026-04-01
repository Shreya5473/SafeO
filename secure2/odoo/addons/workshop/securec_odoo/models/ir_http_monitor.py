import json
import logging

import requests

from odoo import models
from odoo.http import request

from .securec_language import build_language_payload

_logger = logging.getLogger(__name__)

_SENSITIVE_KEYS = {
    "password", "new_password", "confirm_password", "token", "csrf_token",
}


class IrHttpSecureCMonitor(models.AbstractModel):
    _inherit = "ir.http"

    @classmethod
    def _dispatch(cls, endpoint):
        response = super()._dispatch(endpoint)
        try:
            cls._securec_monitor_request()
        except Exception as exc:
            _logger.debug("SecureC global monitor skipped: %s", exc)
        return response

    @classmethod
    def _securec_monitor_request(cls):
        env = request.env
        icp = env["ir.config_parameter"].sudo()
        if icp.get_param("securec.enable_global_monitor", "True") != "True":
            return

        http_request = request.httprequest
        method = (http_request.method or "GET").upper()
        route = http_request.path or ""

        # Keep overhead low and avoid recursion on SecureC internal routes/static assets.
        if route.startswith("/securec/") or route.startswith("/web/assets/"):
            return
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return

        payload = cls._safe_payload_snapshot()
        if len(payload.strip()) < 8:
            return

        policy = cls._active_policy()
        lang_payload = build_language_payload(payload)
        app_name, module_label = cls._resolve_app_labels(route)
        api_url = icp.get_param("securec.api_url", "http://localhost:8001")

        api_payload = {
            "input_text": payload,
            "normalized_input": lang_payload["normalized_input"],
            "language": lang_payload["language"],
            "user_id": str(request.session.uid or "public"),
            "module": module_label,
            "context": {"route": route, "method": method, "global_monitor": True},
        }
        if policy:
            api_payload["region"] = policy.region
            api_payload["policy"] = policy.get_policy_dict()

        try:
            resp = requests.post(f"{api_url}/waf/input", json=api_payload, timeout=2.5)
            if resp.status_code != 200:
                return
            analysis = resp.json()
        except Exception:
            return

        risk_score = float(analysis.get("risk_score", 0.0))
        decision = analysis.get("decision", "allow")
        explanation = analysis.get("explanation", "")
        patterns = analysis.get("detected_patterns", []) or []

        warn_threshold = float(icp.get_param("securec.warn_threshold", "0.30"))
        block_threshold = float(icp.get_param("securec.block_threshold", "0.70"))
        if policy:
            block_threshold = policy.block_threshold

        if risk_score >= block_threshold and decision != "block":
            decision = "block"

        # Avoid spamming logs for low-risk traffic; keep only noteworthy events.
        should_log = decision in {"warn", "block", "sanitize"} or risk_score >= warn_threshold or bool(patterns)
        if not should_log:
            return

        patterns_str = ", ".join(str(p) for p in patterns) if patterns else ""
        user_id = request.session.uid or False
        user = env.user if request.session.uid else env["res.users"]

        log = env["securec.log"].sudo().create({
            "input_text": payload[:1000],
            "risk_score": risk_score,
            "decision": decision,
            "explanation": explanation,
            "detected_patterns": patterns_str,
            "user_id": user_id,
            "module": module_label,
            "detected_language": lang_payload["language"],
            "normalized_text": (
                lang_payload["normalized_input"]
                if lang_payload["normalized_input"] != payload else False
            ),
            "policy_id": policy.id if policy else False,
            "policy_region": policy.region if policy else False,
        })

        env["securec.audit.log"].sudo().log_event({
            "event_type": "waf_block" if decision == "block" else "waf_scan",
            "application": app_name,
            "status": "blocked" if decision == "block" else ("warning" if decision in {"warn", "sanitize"} else "success"),
            "user_id": user_id,
            "login": user.login if user_id else "public",
            "route": route,
            "http_method": method,
            "details": f"Global monitor scan ({module_label}). Decision={decision}. Patterns={patterns_str or 'none'}",
            "risk_score": risk_score,
            "decision": decision,
            "detected_language": lang_payload["language"],
            "policy_region": policy.region if policy else False,
            "securec_log_id": log.id,
        })

    @classmethod
    def _safe_payload_snapshot(cls):
        params = {}
        for key, value in (request.params or {}).items():
            if key in _SENSITIVE_KEYS:
                continue
            if hasattr(value, "filename"):
                params[key] = f"[file:{value.filename}]"
                continue
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
            params[key] = str(text)[:180]

        raw = (request.httprequest.get_data(cache=True, as_text=True) or "")[:1500]
        packed = json.dumps(params, ensure_ascii=False)
        return f"{packed} | raw={raw}"[:3000] if raw else packed[:3000]

    @classmethod
    def _active_policy(cls):
        policy_id = request.session.get("securec_active_policy_id")
        if not policy_id:
            icp = request.env["ir.config_parameter"].sudo()
            policy_id = int(icp.get_param("securec.active_policy_id", 0) or 0)
        if not policy_id:
            return None
        policy = request.env["securec.policy"].sudo().browse(int(policy_id))
        return policy if policy.exists() else None

    @classmethod
    def _resolve_app_labels(cls, route):
        if route.startswith("/web/login") or route.startswith("/web/session"):
            return "Authentication", "Authentication"
        if route.startswith("/website/") or route.startswith("/web/signup"):
            return "Website", "Website"

        if route.startswith("/web/dataset/call_kw/"):
            suffix = route.split("/web/dataset/call_kw/", 1)[1]
            model = suffix.split("/", 1)[0].split("#", 1)[0]
            app_map = {
                "crm": "CRM", "sale": "Sales", "purchase": "Purchase",
                "account": "Accounting", "stock": "Inventory", "hr": "HR",
                "project": "Project", "mrp": "Manufacturing", "helpdesk": "Helpdesk",
                "website": "Website", "mail": "Discuss",
            }
            app = app_map.get((model.split(".", 1)[0] if model else "").lower(), "OdooApp")
            return app, model or "OdooApp"

        return "OdooApp", route.strip("/")[:80] or "OdooApp"
