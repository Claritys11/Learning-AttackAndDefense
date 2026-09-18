# attNdef workspace memory

Purpose: local Attack & Defense CTF training infrastructure for human-understanding-first preparation.

Workspace: /home/claritys/ctf/attNdef

Rules:
- Keep upstream references under refs/ unchanged; build local tooling separately.
- Treat observations as VERIFIED, INFERRED, or UNKNOWN and record source paths/URLs.
- Scope active exploitation to this local lab or explicitly authorized competition targets.
- Before deploying services, check disk capacity and listening ports; do not assume ports are free.
- Never store GZCTF bearer tokens or other secrets in source, reports, or git.
- Separate discovery, exploitation, flag extraction, submission, defense, and replay.
- Optimize for manual reproduction and explainability; avoid blind auto-exploitation.

Reference repositories cloned:
- refs/GZCTF
- refs/gemastik18-final
- refs/Attack-Defense

Initial host constraints observed during reconnaissance:
- /home filesystem: 343G total, 328G used, 9.6G available, 98% used.
- Many TCP listeners already exist, including 80, 443, 8000, 8080, 3000, 4000, 5432, 6379, 9090 and others. Run ss -ltnup immediately before any deployment and choose verified-free ports.

GZCTF A&D facts from checked-out source/docs:
- Player A&D route prefix: /api/Game/{id}/Ad.
- Targets: GET /api/Game/{id}/Ad/Targets.
- Flag submission: POST /api/Game/{id}/Ad/Submit with JSON {"flags":[...]}; Bearer ad_... accepted.
- Per-user token lifecycle: POST/GET/DELETE /api/Game/{id}/Ad/Token; plaintext returned only on POST rotation.
- Bearer resolution hashes the presented token and requires accepted participation plus current roster membership and non-banned user.
- Target objects and exact JSON model fields still need to be extracted from AdSubmitModel.cs / relevant response models.
- A&D flags are read by services from GZCTF_FLAG_FILE (/flag on Docker, /gzctf-flag/flag on Kubernetes), not GZCTF_FLAG.
- Docker A&D uses one container per accepted team/challenge; exposed service port is challenge ExposePort, default 80; target IP/port are dynamic.

Reconnaissance report delivered to user and accepted for continuity. Preserve its findings: repositories are cloned under refs/, GZCTF A&D uses dynamic targets via GET /api/Game/{id}/Ad/Targets and flag submission via POST /api/Game/{id}/Ad/Submit with Bearer ad_ tokens, and no service has been deployed. Next phase: finish source-grounded endpoint/model extraction, resource analysis, and a proposal before implementation.
