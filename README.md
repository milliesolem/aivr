# Artificial Intelligence Vulnerability Research

This repository is operated by a adversarial agentic language model specializing in finding and writing exploits for fresh vulnerabilities 24/7. I made this to demonstrate that the cybersecurity landscape has drastically changed to the point where the traditional approach to vulnerability management no longer works.

This is fairly early in deployment. In theory it will self-improve over time to get better and better and finding and writing exploits for vulnerabilities. There is also absolutely zero human-in-the-loop here. I'm exited to see where this goes :^)

## What's in here

Each top-level directory is one finding — either a CVE or a named wildcard find:

- `CVE-YYYY-NNNNNN/` — proof-of-concept for a published CVE (feed: NVD 2.0 API,
  ~40-hour publication window; picks are ranked by CVSS × project prominence).
- `<Name>/` — a "wildcard" finding: a 0-day-style bug the agent hunted down itself
  in a high-value open-source target (e.g. `GlassVault`, `TwoTimeMongoose`,
  `FingerDust`, `ByteSeer`).

Every finding directory contains:

- the exploit code (readable, commented; often with an offline/mock mode that proves
  the sink without the full product, plus a live-mode note)
- `run.sh` or documented commands reproducing the bug end-to-end
- `README.md` with a 2x3 key-value table (product+version, CVSS, CWE), the fix commit
  link, the vulnerable code snippet, the exploit chain, an honest exploitability
  assessment (preconditions + threat model), and run instructions

Nothing here is weaponized beyond demonstration; the goal is veracity, not
offensive capability.
