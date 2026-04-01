# SafeO — Pitch deck script (copy into slides)

**Product name:** SafeO (UI and pitch). Technical module id can stay `securec_odoo` for upgrades.

---

## Slide 1 — Title

**SafeO**  
The AI-assisted security layer built for Odoo — stop bad input before it becomes a breach.

Team: `Teamname_participantname`  
Odoo Buildathon

*Notes:* We complement Odoo patches; we add inline detection, policy, and proof.

---

## Slide 2 — Hook

Your CRM, website, and portal are where money and trust live — and where attackers test passwords, poison fields, and probe APIs.

---

## Slide 3 — Problem (numbers; cite “industry reports” verbally)

- Compromised or abused credentials are consistently among the **top initial access vectors** in major annual breach analyses (e.g. DBIR-class reports).
- Credential stuffing can represent a **large fraction of login attempts** in measured environments (research often cites roughly **mid-teens to mid-twenties percent** in some samples — say “up to ~1 in 4 attempts in some enterprise telemetry”).
- Many SMEs run Odoo **without** 24×7 SOC — they need visibility **inside** the app, not only at the network edge.

---

## Slide 4 — Odoo reality

- Odoo, like any major ERP, ships **security advisories and CVEs** — including issues classes around **validation**, **disclosure**, and **identity** edges (cite 2024+ advisories / NVD in Q&A).
- Custom modules, **website forms**, and **RPC** expand surface area beyond a vanilla demo.

---

## Slide 5 — Who suffers

- SME ops teams without dedicated SecOps.
- UAE / regional adopters with compliance pressure.
- Odoo partners asked: “What monitors our **forms** and **logins**?”

---

## Slide 6 — What SafeO is

User → Odoo (CRM · Website · Portal) → **SafeO** (rules + statistical ML + optional LLM) → block / warn / log → **one dashboard**.

All on **your** Odoo instance.

---

## Slide 7 — Technical novelty

1. **Tiered intelligence** — fast path always on; **LLM only** when uncertainty is high or via **sampling** → **fewer API calls, lower cost**.  
2. **Explainable** scores — patterns + narrative, not a black box.  
3. **Policy engine** — regional thresholds (UAE / EU / US / global story).  
4. **Optional cache** — normalized payload hash / TTL to cut repeated probe cost.

*Demo metric idea:* “LLM calls avoided” on dashboard.

---

## Slide 8 — Live demo checklist

- Live Attack Lab → score + logs.  
- CRM → block malicious lead.  
- Website / signup (if on) → blocked submission.  
- **Activity feed** → failed login + WAF in one timeline.  
- **Exposure signal** — illustrative, **disclaimed** (not real financial loss).

---

## Slide 9 — Why not “just Cloudflare?”

Edge WAF ≠ Odoo **business context**. SafeO aligns with **forms, ORM saves, and tenant workflows** — **complementary**.

---

## Slide 10 — Metrics (honest)

- Track: **% of attacks blocked before persistence** (pilot).  
- Track: **LLM calls per 1k requests** before/after gating (claim only measured numbers).  
- Goal framing: designed for **large reduction** in LLM calls (e.g. 60–90%) — validate in your environment.

---

## Slide 11 — Roadmap

- LLM gating + cache.  
- Per-user anomaly baselines from audit data.  
- Partner packaging + evidence export.

---

## Slide 12 — Close

**SafeO** — security that ships **inside Odoo**, with an honest threat model and a demo you can run in minutes.

*Q&A:* Scope = this deployment; money figures = **illustrative**; still **patch Odoo**.

**Design:** one big number per slide; one dashboard screenshot + one “blocked” dialog.
