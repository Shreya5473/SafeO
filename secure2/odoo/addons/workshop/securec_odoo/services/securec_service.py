"""
securec_service.py
~~~~~~~~~~~~~~~~~~
Central service layer for SecureC WAF integration.

Call `SecureCService(env).log_securec_event(data)` from anywhere in Odoo
to record a complete security interaction, including:
  - Creating a securec.event record
  - Creating per-agent securec.agent.log records
  - Updating the user's securec.user.profile (anomaly scoring)

This service abstracts all WAF API calls so models only need to call
a single function.
"""
import json
import logging
import requests
from typing import Optional

from odoo import _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

# Module name → Selection key mapping for normalization
MODULE_KEY_MAP = {
    'CRM':        'crm',
    'crm':        'crm',
    'HR':         'hr',
    'hr':         'hr',
    'Sales':      'sales',
    'sales':      'sales',
    'Purchase':   'purchase',
    'purchase':   'purchase',
    'Accounting': 'accounting',
    'accounting': 'accounting',
    'mail':       'mail',
    'Mail':       'mail',
    'system':     'system',
    'System':     'system',
}


class SecureCService:
    """
    Stateless service class. Instantiate with the current Odoo env:

        svc = SecureCService(self.env)
        event = svc.log_securec_event(request_data, response_data)
    """

    def __init__(self, env):
        self.env = env

    # ── Internal Helpers ──────────────────────────────────────────────────

    def _api_url(self) -> str:
        return self.env['ir.config_parameter'].sudo().get_param(
            'securec.api_url', 'http://localhost:8001'
        )

    def _normalize_module(self, module_str: str) -> str:
        return MODULE_KEY_MAP.get(module_str, 'generic')

    # ── Core WAF Call ─────────────────────────────────────────────────────

    def call_waf_input(
        self,
        input_text: str,
        module: str = 'generic',
        context: dict = None,
    ) -> dict:
        """
        POST /waf/input and return the parsed response dict.
        Returns a safe fallback dict if the API is unreachable (fail-open).
        """
        payload = {
            'input_text': input_text,
            'user_id': str(self.env.user.id),
            'module': module,
            'context': context or {},
        }
        try:
            resp = requests.post(
                f"{self._api_url()}/waf/input",
                json=payload,
                timeout=5,
            )
            if resp.status_code == 200:
                return resp.json()
            _logger.warning("SecureC /waf/input returned %s", resp.status_code)
        except Exception as exc:
            _logger.warning("SecureC /waf/input unreachable: %s", exc)

        # Fail-open: allow the action but flag as failed
        return {
            'risk_score': 0.0,
            'decision': 'allow',
            'explanation': 'SecureC API unreachable (fail-open)',
            'detected_patterns': [],
            'agents': [],
            'request_id': 'offline',
            '_failed': True,
        }

    def call_waf_output(self, output_text: str, module: str = 'generic') -> dict:
        """POST /waf/output and return the parsed response dict."""
        payload = {
            'output_text': output_text,
            'user_id': str(self.env.user.id),
            'module': module,
        }
        try:
            resp = requests.post(
                f"{self._api_url()}/waf/output",
                json=payload,
                timeout=5,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            _logger.warning("SecureC /waf/output unreachable: %s", exc)
        return {
            'risk_score': 0.0,
            'decision': 'allow',
            'explanation': 'SecureC API unreachable (fail-open)',
            'detected_patterns': [],
            'agents': [],
            'request_id': 'offline',
            '_failed': True,
        }

    def call_waf_behavior(self, action: str, module: str = 'generic') -> dict:
        """POST /waf/behavior — fire-and-forget, never raises."""
        try:
            requests.post(
                f"{self._api_url()}/waf/behavior",
                json={
                    'user_id': str(self.env.user.id),
                    'action': action,
                    'module': module,
                },
                timeout=2,
            )
        except Exception:
            pass
        return {}

    # ── Main Logging Entry Point ──────────────────────────────────────────

    def log_securec_event(
        self,
        request_data: dict,
        response_data: dict,
        event_type: str = 'input',
        module: str = 'generic',
        raise_on_block: bool = True,
    ) -> 'securec.event':
        """
        Full pipeline:
          1. Parse the response from the SecureC API.
          2. Create a securec.event record.
          3. Create securec.agent.log records for each agent.
          4. Update the user's securec.user.profile.
          5. Optionally raise UserError if decision == 'block'.

        Args:
            request_data:   Dict sent to /waf/input (or /waf/output).
            response_data:  Dict received from the SecureC API.
            event_type:     One of 'input', 'output', 'behavior', 'simulation'.
            module:         Human-readable module name (normalized automatically).
            raise_on_block: If True, raise Odoo UserError when WAF blocks.

        Returns:
            securec.event record (or empty recordset on failure).
        """
        try:
            # 1. Parse response fields
            risk_score  = float(response_data.get('risk_score', 0.0))
            decision    = response_data.get('decision', 'allow')
            explanation = response_data.get('explanation', '')
            patterns    = response_data.get('detected_patterns', [])
            agents      = response_data.get('agents', [])
            sanitized   = response_data.get('sanitized_text')
            failed      = response_data.get('_failed', False)

            norm_module = self._normalize_module(module)
            status = 'failed' if failed else 'success'

            # 2. Create the securec.event record
            event_vals = {
                'user_id':          self.env.user.id,
                'module':           norm_module,
                'event_type':       event_type,
                'input_text':       request_data.get('input_text', '')[:5000],
                'output_text':      request_data.get('output_text', '')[:5000],
                'risk_score':       risk_score,
                'decision':         decision if decision in ('allow', 'warn', 'block', 'sanitize') else 'allow',
                'status':           status,
                'explanation':      explanation,
                'detected_patterns': ', '.join(patterns) if patterns else '',
                'request_payload':  json.dumps(request_data, default=str)[:10000],
                'response_payload': json.dumps(response_data, default=str)[:10000],
            }
            event = self.env['securec.event'].sudo().create(event_vals)

            # 3. Create per-agent logs (batch insert)
            agent_vals_list = []
            for ag in agents:
                agent_vals_list.append({
                    'event_id':         event.id,
                    'agent_name':       ag.get('agent_name', 'Unknown'),
                    'decision':         ag.get('decision', 'allow') if ag.get('decision') in ('allow','warn','block','sanitize') else 'allow',
                    'confidence':       float(ag.get('confidence', 0.0)),
                    'weight':           float(ag.get('weight', 1.0)),
                    'reasoning':        ag.get('explanation', ''),
                    'detected_patterns': ', '.join(ag.get('detected_patterns', [])),
                })
            if agent_vals_list:
                self.env['securec.agent.log'].sudo().create(agent_vals_list)

            # 4. Update user profile
            self._update_user_profile(self.env.user.id, decision, risk_score, norm_module, event.id)

            # 5. Raise on block — but FIRST commit the security log in a NEW, INDEPENDENT
            #    cursor so it is persisted BEFORE the outer transaction is rolled back by
            #    the UserError.  This is the standard Odoo pattern for "write-then-rollback"
            #    scenarios (e.g. sending emails after a failed payment).
            if raise_on_block and decision == 'block':
                try:
                    registry = self.env.registry
                    with registry.cursor() as new_cr:
                        new_env = self.env(cr=new_cr)
                        new_env['securec.log'].sudo().create({
                            'input_text':        request_data.get('input_text', '')[:1000],
                            'risk_score':        risk_score,
                            'decision':          'block',
                            'explanation':       explanation,
                            'detected_patterns': ', '.join(patterns) if patterns else '',
                            'user_id':           self.env.uid,
                            'module':            norm_module,
                        })
                        # The context-manager commits new_cr on clean exit —
                        # this write survives even if the outer transaction rolls back.
                except Exception as log_exc:
                    _logger.warning(
                        "SecureC: separate-cursor security log write failed: %s", log_exc
                    )

                raise UserError(_(
                    "🛡️ SecureC blocked this operation.\n\n"
                    "Risk Score: %(score)s%%  |  Decision: BLOCK\n\n"
                    "Reason: %(explanation)s\n\n"
                    "Detected patterns: %(patterns)s\n\n"
                    "%(sanitized)s"
                    "Please review the flagged content and try again.",
                    score=round(risk_score * 100),
                    explanation=explanation or 'N/A',
                    patterns=', '.join(patterns) or 'N/A',
                    sanitized=(f"Suggested safe version:\n{sanitized}\n\n" if sanitized else ''),
                ))

            return event

        except UserError:
            raise
        except Exception as exc:
            _logger.error("SecureCService.log_securec_event failed: %s", exc, exc_info=True)
            return self.env['securec.event'].browse()

    # ── Full WAF + Log Pipeline ───────────────────────────────────────────

    def scan_and_log_input(
        self,
        input_text: str,
        module: str = 'generic',
        context: dict = None,
        raise_on_block: bool = True,
    ) -> dict:
        """
        Convenience wrapper: call WAF, log event, return response.
        Use this in model overrides instead of calling requests directly.
        """
        request_data = {
            'input_text': input_text,
            'user_id': str(self.env.user.id),
            'module': module,
            'context': context or {},
        }
        response_data = self.call_waf_input(input_text, module=module, context=context)
        self.log_securec_event(
            request_data, response_data,
            event_type='input', module=module,
            raise_on_block=raise_on_block,
        )
        self.call_waf_behavior(action=f'{module}_input', module=module)
        return response_data

    def scan_and_log_output(
        self,
        output_text: str,
        module: str = 'generic',
    ) -> dict:
        """
        Convenience wrapper for output scanning.
        Returns the (possibly sanitized) response data.
        """
        request_data = {'output_text': output_text, 'module': module}
        response_data = self.call_waf_output(output_text, module=module)
        self.log_securec_event(
            request_data, response_data,
            event_type='output', module=module,
            raise_on_block=False,   # Output scans never raise — they sanitize
        )
        return response_data

    def log_simulation_results(self, results: list, module: str = 'system') -> 'securec.event':
        """
        Create a securec.event of type 'simulation' and bulk-insert all
        securec.attack.simulation sub-records from the results list.
        """
        if not results:
            return self.env['securec.event'].browse()

        detected = sum(1 for r in results if r.get('detected'))
        total = len(results)
        rate = round(detected / total * 100, 1) if total else 0.0

        event_vals = {
            'user_id':    self.env.user.id,
            'module':     self._normalize_module(module),
            'event_type': 'simulation',
            'risk_score': 0.0,
            'decision':   'allow',
            'status':     'success',
            'explanation': f"Attack simulation: {detected}/{total} attacks detected ({rate}%)",
            'request_payload':  json.dumps({'simulation': True, 'total': total}, default=str),
            'response_payload': json.dumps({'detected': detected, 'detection_rate': rate}, default=str),
        }
        event = self.env['securec.event'].sudo().create(event_vals)
        self.env['securec.attack.simulation'].create_from_simulation_response(results, event_id=event.id)
        return event

    # ── Internal: Update User Profile ─────────────────────────────────────

    def _update_user_profile(
        self,
        user_id: int,
        decision: str,
        risk_score: float,
        module: str,
        event_id: int,
    ):
        """Get-or-create the user profile and update counters / anomaly score."""
        try:
            Profile = self.env['securec.user.profile']
            profile = Profile.get_or_create_profile(user_id)
            profile.increment_action(decision, risk_score, module=module, event_id=event_id)
        except Exception as exc:
            _logger.warning("SecureC: profile update failed for user %s: %s", user_id, exc)
