# SafeO — Award-Strategy & Feature Plan (Odoo Buildathon)

**Product name (user-facing):** SafeO  
**Technical module id:** keep `securec_odoo` + `securec.*` parameters for stable upgrades and DB keys.

---

## 1. Real-world problem (what enterprises and Odoo shops actually face)

### 1.1 Platform risk is real (Odoo-specific)

Odoo, like any large ERP + web surface, ships security fixes because attackers and researchers find issues:

| Theme | Why it matters for “top companies” running Odoo |
|--------|--------------------------------------------------|
| **Input / RPC validation** | Authenticated abuse of business logic (crafted RPC) can bypass what admins assume is “just CRUD.” Public advisories in the **2024** cycle included **critical/high** issues around **improper input validation** and related classes (e.g. issues discussed under Odoo security advisories for 2024). |
| **Mail / messaging surface** | Email and chatter are high-trust channels; **information disclosure** classes of bugs hit orgs that rely on Odoo as the system of record for customer comms. |
| **OAuth / session** | SaaS-style deployments multiply identity edges; session and OAuth-class issues create **privilege** and **account takeover** risk if not patched quickly. |

**Takeaway for judges:** SafeO is not “because Odoo is bad” — it is **defense-in-depth** because Odoo is **valuable** (CRM, website, portal, integrations) and **attackers follow value**.

### 1.2 What attackers do in practice (language you can say on stage)

- **Credential abuse:** Industry reporting (e.g. **Verizon DBIR** lines of research on **credential stuffing**) highlights stuffing as a large share of **authentication attempts** in many environments (order-of-magnitude **teens–twenty percent** of auth traffic in cited analyses — use wording “up to ~1 in 4–5 attempts in some enterprise samples” rather than a fake exact for Odoo).
- **Stolen passwords as initial access:** Multiple annual reports place **compromised credentials** among the **top 2–3** initial access vectors in breaches (exact % moves by year; cite “consistently top tier” in slide).
- **SMB / mid-market gap:** Smaller teams run Odoo **without** 24×7 SOC, **without** edge WAF tuning, and **with** website + portal + CRM exposed — exactly where **inline app-layer** monitoring helps.

### 1.3 Stats to use in pitch (honest framing)

Use **ranges** and **sources**; avoid fake precision:

- **“Credential-related paths appear in a large share of reported breaches year over year (major industry breach reports).”**
- **“Credential stuffing can represent a substantial fraction of login traffic in measured environments (DBIR-style supplemental analyses).”**
- **“Odoo’s security advisories show ongoing hardening against authenticated abuse, disclosure, and validation issues — i.e. the platform is actively targeted and fixed.”**

If a judge asks “is that Odoo-specific?” — answer: **“No; it’s the threat model for any internet-facing ERP. SafeO specializes the controls and telemetry inside Odoo.”**

---

## 2. What SafeO should be (positioning)

**One sentence:**  
SafeO is an **AI-assisted, policy-aware input and activity firewall** that lives **inside Odoo**, scores risky text and suspicious flows, **blocks or warns** where configured, and gives **one security command center** for demos and operations.

**Not claimed:** protecting random third-party sites; replacing Cloudflare; “100% catch rate.”

---

## 3. Technically novel / “mind-blowing” features (planned, prioritized)

### Tier A — **Suitable for buildathon** (high judge ROI, defensible)

| ID | Feature | Technical idea | Why novel / credible |
|----|---------|----------------|---------------------|
| **A1** | **Tiered intelligence (LLM cost control)** | Pipeline: **fast path** = deterministic + lightweight statistical ML (entropy, bursts, decoding, pattern tiers) always on. **Slow path** = LLM only if `uncertainty_score` in band OR random **sample rate** (e.g. 5–15%) for drift detection. | Reduces OpenRouter cost **without** hiding attacks; you can show **“LLM calls avoided: N”** on dashboard. |
| **A2** | **Semantic / structural cache** | Cache WAF decisions by **normalized payload hash** + **length bucket** + **language** with short TTL; optional **SimHash** for near-duplicates. | Cuts repeated probe traffic (bots, scanners) — real cost win. |
| **A3** | **Ensemble “high-end ML” (honest)** | Keep extending **non-LLM** signals: compression anomaly, token-burst, iterative decode, multilingual normalization — fused with **learned weights** or simple calibrated score. | Judges hear “ensemble + explainability” without pretending you trained a 70B model. |
| **A4** | **Command center visuals** | You already have mix bars + feed; add **time-bucket timeline** (events per hour last 24h) and **severity funnel** (allow/warn/block) from DB — pure SQL + existing bar CSS. | Looks “SOC” without new chart libraries. |

### Tier B — **Only if time remains**

| ID | Feature | Note |
|----|---------|------|
| B1 | **Anomaly baseline per user** | Rolling z-score on request rate / fail rate from `securec.audit.log` — “behavior” without big ML. |
| B2 | **Exportable “evidence pack”** | PDF/CSV of last incident for auditors — great story for UAE enterprise. |

### Tier C — **Out of scope (do not promise)**

- Replacing Odoo security patches  
- “Unbreakable” claims  
- Smart pricing / unrelated ERP features (dilutes story)

---

## 4. Implementation phases (when you say “go”)

1. **Phase 0 — Branding:** Manifest `name`, menus, OWL dashboard strings, user-facing errors → **SafeO**; keep `securec_*` field names.  
2. **Phase 1 — LLM gating + metrics:** In FastAPI `waf` router: only call LLM if heuristics leave mid-band uncertainty; expose `llm_calls_skipped` / `llm_calls` in metrics API.  
3. **Phase 2 — Decision cache:** Small in-memory or Redis-optional cache (start in-process dict + TTL for single-node demo).  
4. **Phase 3 — Timeline chart:** New JSON-RPC returning `hourly_counts[24]`; OWL bar row.  
5. **Phase 4 — Polish:** Jira, Arabic presets, judge checklist panel (optional).

---

## 5. Workshop alignment (Buildathon scoring)

- **Models / fields / compute:** `securec.log`, `securec.audit.log`, policy model — already map to Day 1–2.  
- **Widgets / actions / dashboard:** OWL client action + JSON-RPC — Day 3.  
- **Constraints / advanced views:** ACLs, settings, optional SQL constraint on score range — Day 4.

---

## 6. References to bookmark (for judges Q&A)

- Odoo security advisories and CVE listings (NVD / Odoo).  
- Verizon DBIR (initial access, credentials, web apps).  
- NCSC / ICO-style guidance for SMEs (defense in depth, logging).
