# Day 4/7 — Basic Python Auth Log Parser

Beginner cybersecurity portfolio project: parse Linux auth logs and summarize failed SSH logins by **username** and **source IP**.

## Goal
Build a minimal, legal/ethical script that helps detect brute-force patterns from auth logs.

---

## Research (2–3 credible references)

1. **OWASP Logging Cheat Sheet**  
   https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

2. **MITRE ATT&CK T1110 — Brute Force**  
   https://attack.mitre.org/techniques/T1110/

3. **SSH failed login log patterns (practical guide)**  
   https://www.simplified.guide/ssh/access-failed-show

## Key learning points

- Security logging should be **consistent and structured** so events can be aggregated and analyzed (OWASP).
- Repeated failed authentication attempts are a core indicator of **brute-force activity** (MITRE T1110).
- Typical OpenSSH failure lines expose the fields we need for quick triage:
  - attempted username
  - source IP
  - timestamp/host metadata
- A useful beginner-first detector can stay simple: regex parse + counters + top offenders.

---

## Execute

### Files
- `auth_log_parser.py` — runnable parser
- `sample_auth.log` — sample Linux auth log

### Run

```bash
cd /Users/joshuasack/.openclaw/workspace/projects/daily-cyber/2026-03-13-auth-log-parser
python3 auth_log_parser.py --log sample_auth.log
```

Optional:

```bash
python3 auth_log_parser.py --log sample_auth.log --top 10
```

### Expected output (example)

- Total failed login attempts
- Top targeted users
- Top source IPs

---

## Legal / Ethical Note

Use this project only on systems and logs you are authorized to access. This tool is for defensive monitoring and learning.

---

## Push

If GitHub CLI (`gh`) is authenticated, publish to a public repo:

- Target owner: `ZombieDuckling`
- Suggested repo: `cyber-day4-auth-log-parser`
