# Roadmap Belajar Attack & Defense untuk LKS

Roadmap ini disesuaikan dengan kisi-kisi LKS 2024/2025 dan model platform GZCTF/TCP1P. Targetnya bukan sekadar bisa menjalankan solver, tetapi bisa menjaga service tetap hidup sambil memahami, mengeksploitasi, menutup, dan menguji ulang bug.

Aturan lab: seluruh latihan attack hanya pada VM/container/fixture milik sendiri atau kompetisi yang secara eksplisit mengizinkan. Jangan menjalankan scanner, exploit, credential testing, atau exfiltration ke target publik yang tidak diotorisasi.

## Hasil akhir yang harus dikuasai

Pada akhir roadmap, kamu harus bisa:

1. Membaca topologi dan membangun asset/endpoint map.
2. Menjalankan enumeration yang terukur dan tidak merusak service.
3. Menemukan root cause dari source code dan konfigurasi.
4. Membuat PoC exploit yang reproducible terhadap fixture sendiri.
5. Membuat patch minimal yang mempertahankan SLA checker.
6. Memantau event, process, auth, network, dan file changes.
7. Membuat solver modular yang menerima target dinamis.
8. Menjalankan attack wave terjadwal, extract, dedup, dan submit melalui adapter resmi.
9. Menulis rollback dan regression test.
10. Menjelaskan evidence: apa yang terbukti, apa yang hanya indikasi, dan apa yang belum diketahui.

## Model kompetisi GZCTF/TCP1P

```text
event manifest + challenge.yml
        -> review/import/build
        -> instance service per team
        -> warmup
        -> repeated tick/round
             |-- defender: inspect, patch, keep SLA green
             |-- attacker: target opponent instances, capture flags
             |-- checker: legitimate workflow and health
             |-- scoring: attack/defense/flag lifetime/submission rules
             |-- telemetry: live feed, access, traffic, honeypot
             |-- forensics: snapshots and change manifests
        -> evidence + score + human anti-cheat review
```

Perbedaan tiga aktor harus selalu jelas:

- Attacker: menyerang instance lawan yang muncul di registry resmi, bukan melakukan internet-wide scan.
- Defender: memperbaiki instance sendiri tanpa mematikan alur normal yang dites checker.
- Checker/SLA: memvalidasi fungsi normal; biasanya bukan jalur exploit.

## Cara belajar: satu siklus untuk setiap topik

Gunakan siklus 6 langkah berikut pada setiap module:

1. Konsep: jelaskan trust boundary, asset, input, sink, dan dampak.
2. Observe: lihat service normal dengan logging dan packet/process observation.
3. Reproduce: buat fixture vulnerable kecil di localhost.
4. Attack: buat PoC minimal, deterministic, dan bounded.
5. Defend: patch root cause, bukan sekadar memblokir satu payload.
6. Verify: jalankan SLA normal, replay exploit, negative test, dan rollback.

Simpan hasil sebagai:

```text
labs/<topic>/README.md
labs/<topic>/vulnerable/
labs/<topic>/patched/
labs/<topic>/attack.py
labs/<topic>/defense.md
labs/<topic>/tests/
labs/<topic>/evidence/
```

## Fase 0 — Setup dan Linux dasar (minggu 1)

### Target
Mampu bekerja cepat di shell, memahami permission, service, package, process, network, dan log.

### Materi

- Linux filesystem, `/proc`, `/sys`, `/var/log`.
- User/group, UID/GID, sudo, SUID/SGID, ACL, umask.
- `systemctl`, `journalctl`, process tree, signal.
- Package install/update dan verifikasi file.
- TCP/UDP, DNS, routing, interface, listening socket.
- SSH key, `known_hosts`, `sshd_config`, port forwarding konsep.
- VPN concept: route table, tunnel interface, private challenge subnet.

### Praktik aman

```bash
id; groups; sudo -l
ps auxf; ss -lntup
ip addr; ip route
journalctl -p warning -b
find /tmp -perm -4000 -type f 2>/dev/null
```

Jalankan hanya pada VM sendiri. Buat akun `player`, `service`, dan `admin`; uji permission dengan file dummy.

### Lulus jika

- Bisa menjelaskan mengapa service tertentu berjalan sebagai user non-root.
- Bisa menemukan listener dan proses pemiliknya.
- Bisa SSH ke VM lab dan menjelaskan route VPN lab tanpa membocorkan key.
- Bisa mengubah permission, install package, dan rollback perubahan.

## Fase 1 — Enumeration dan asset mapping (minggu 2)

### Mapping kisi-kisi

- LKS 2025: Enumeration.
- LKS 2024: port scanning dan system security.
- GZCTF: target dinamis per team/challenge dan private access plane.

### Attack skills

- Scope/allowlist sebelum scan.
- TCP connect scan ringan terhadap subnet lab.
- Service/version identification.
- HTTP route/header/status mapping.
- DNS/hosts/routes dan exposed files.
- Read-only config and source inventory.

### Defense skills

- Kurangi surface: close unused ports, bind interface tepat, remove debug/admin exposure.
- Service inventory dan expected-port baseline.
- Alert untuk port/process baru.
- Jangan mengandalkan hidden URL sebagai security control.

### Deliverable

`asset_inventory.json`, `endpoint_map.md`, baseline listening ports, dan test yang mendeteksi port tidak diharapkan.

### Gate

Tidak boleh lanjut jika belum bisa menjawab: service apa, port berapa, proses siapa, user apa, input utama apa, dan data sensitif mengalir ke mana.

## Fase 2 — Source review dan threat modeling (minggu 3)

### Mapping kisi-kisi

- LKS 2025: source code review.
- LKS 2024: system security, CVE mitigation.

### Checklist review

- Authentication vs authorization.
- Input source → parser → validation → sink.
- File read/write, command execution, template rendering.
- SQL/NoSQL query construction.
- Deserialization and path traversal.
- Secret/key loading and error messages.
- Race conditions and state transitions.
- Dependency versions and unsafe defaults.
- Container privileges, capabilities, mounted sockets, writable paths.

### Deliverable

Untuk setiap bug:

```text
entry point -> precondition -> vulnerable operation -> primitive
-> impact/flag path -> minimal PoC -> root cause -> patch -> regression
```

Gunakan level hint 0–5 agar belajar bertahap: no hint, concept, component, function, primitive, full exploit.

## Fase 3 — CVE exploit dan mitigation (minggu 4)

### Workflow

1. Identifikasi versi dan komponen.
2. Baca advisory/vendor patch dan diff yang relevan.
3. Reproduce di image/VM vulnerable lokal.
4. Bangun PoC paling kecil.
5. Amati event/process/network effect.
6. Patch dengan upgrade/config/code change.
7. Jalankan normal-flow SLA dan PoC ulang.
8. Verifikasi versi/package/file hash.

### Jangan lakukan

- Jangan copy exploit dari internet lalu jalankan ke target publik.
- Jangan menganggap version match berarti vulnerable.
- Jangan menutup port sebagai satu-satunya mitigation jika service harus tetap tersedia.

### Deliverable

Satu advisory report dengan vulnerable image, patched image, exploit test, mitigation rationale, dan rollback.

## Fase 4 — Authentication: SSH, OAuth2, AD (minggu 5–6)

### SSH

- Key vs password authentication.
- Host key verification.
- `authorized_keys`, forced command, agent forwarding risk.
- Bastion/jump host dan least privilege.
- Audit login success/failure.

### OAuth2/OIDC

- Role: resource owner, client, authorization server, resource server.
- Authorization code + PKCE.
- State, nonce, redirect URI, issuer/audience, token expiry.
- JWT signature algorithm and key validation.
- Scope vs role; authentication tidak otomatis authorization.

### Active Directory

- Domain/user/group/computer/trust basics.
- LDAP/Kerberos concept.
- GPO and service accounts.
- Event logs and account lockout.
- Delegation/least privilege.

Latihan hanya pada AD lab/GOAD-like environment milik sendiri. Jangan password spray ke jaringan eksternal.

### Deliverable

Auth matrix: actor × endpoint × required role/scope × expected result × audit event.

## Fase 5 — Privilege escalation (minggu 7)

### Linux

- Sudo rules, SUID/SGID, capabilities.
- Writable service/config/script.
- Cron/systemd timer.
- PATH/library hijack dalam lab.
- Container boundary dan dangerous mounts.

### Windows

- Service permissions.
- Scheduled task.
- Weak directory/file ACL.
- Unquoted service path concept.
- Token/privilege and event logs.

### Defense

- Remove unnecessary privileges.
- Root-owned immutable configuration where appropriate.
- Explicit absolute paths.
- Service accounts with minimal rights.
- Monitor changes to task/service/config.

### Gate

Setiap escalation harus punya: initial user, misconfiguration, exact permission edge, proof in lab, patch, and detection event.

## Fase 6 — Event dan process monitoring (minggu 8)

### Linux

- `auditd`, journald, process tree, exec events.
- File integrity baseline.
- Auth logs, sudo logs, SSH logs.
- Socket/process correlation.

### Windows

- Event Viewer/PowerShell logs.
- Security log, process creation, scheduled task, service changes.
- PowerShell logging and account policy.

### Detection exercises

- Detect unexpected child process from web service.
- Detect new listener and outbound connection.
- Detect sensitive file read.
- Detect persistence via cron/system scheduler.
- Correlate timestamp, user, PID, source IP, and command line.

### Deliverable

A small detector that emits structured events with `source`, `timestamp`, `actor`, `action`, `evidence`, `confidence`, and `severity`.

## Fase 7 — Data exfiltration, firewall, and honeypots (minggu 9)

### Attack lab

- Model sensitive data and allowed egress.
- Demonstrate exfil only between two localhost fixtures.
- Compare DNS/HTTP/TCP egress patterns.
- Test output size, encoding, and retry behavior.

### Defense

- Default-deny egress where challenge design permits.
- Explicit service-to-service allowlist.
- Firewall zones and logging.
- Canary/honeypot files and routes.
- Alert-only honeypots: signal, not automatic ban.

### GZCTF connection

The referenced fork describes flag-egress and honeypot evidence, but those signals have attribution limits. Treat shared IP, timing, and bait hits as evidence that needs corroboration.

## Fase 8 — Code patching and SLA preservation (minggu 10)

### Patch protocol

```text
snapshot/hash
  -> identify root cause
  -> dry-run diff
  -> backup
  -> apply minimal patch
  -> reload/restart
  -> health check
  -> legitimate SLA flow
  -> replay exploit
  -> evidence + rollback path
```

Untuk challenge web, checker harus tetap bisa melakukan register/login/core API/report normal. Untuk binary, create/show/edit/delete normal harus tetap berjalan setelah dangling pointer diperbaiki.

### Deliverable

- Idempotent patch strategy.
- Dry-run output.
- Backup and rollback.
- Exploit replay must fail.
- SLA test must pass.
- Test for regression and unintended information leak.

## Fase 9 — GZCTF/TCP1P competition automation (minggu 11)

Gunakan `attnndef` sebagai orchestrator, bukan sebagai exploit monolith.

### Struktur solver

```text
competition_attacks/
  web_01.py
  pwn_01.py
  auth_01.py
competition_checks/
  web_01.py
  pwn_01.py
platform_adapter/
  target_refresh.py     # exact official API, verified separately
  submit.py             # exact official API, explicit live gate
```

### Per wave

```bash
attnndef discover --role own
attnndef health --role own --check-fn competition_checks.web_01:health
attnndef patch --target-id own-web --mode dry-run ...
attnndef patch --target-id own-web --mode apply ...
attnndef replay --target-id own-web ...
attnndef wave \
  --solver web=competition_attacks.web_01:attack_fn \
  --solver pwn=competition_attacks.pwn_01:attack_fn \
  --endpoint https://OFFICIAL-VERIFIED-ENDPOINT
```

Mulai dari dry-run. Live submission hanya setelah endpoint/schema/auth/rate-limit diverifikasi dari event resmi. Target IP/port harus di-refresh; jangan hardcode.

### Score-oriented priorities

1. Keep own SLA green.
2. Patch high-impact root causes quickly.
3. Attack with low-noise, bounded strategies.
4. Submit only validated, deduplicated flags.
5. Track accepted/rejected/expired and stale target.
6. Use live feed as telemetry, not as proof of exploit success.

## Fase 10 — Mock competition dan capstone (minggu 12)

Buat mini-lomba lokal:

- 2 teams mock.
- Web service dengan auth bug + template/path bug.
- TCP/binary service dengan memory/state bug.
- Checker normal-flow.
- Dynamic per-team flags.
- Tick 60 detik.
- Own/enemy registry.
- One patch variant and rollback.
- Event/evidence dashboard sederhana.

### Capstone acceptance criteria

- Enumeration menemukan seluruh service yang didefinisikan.
- Solver strategy memilih target berdasarkan tag.
- Attack wave bounded dan menghasilkan report.
- Flag dedup bekerja.
- Submit adapter default dry-run.
- Defense patch menutup exploit.
- SLA tetap lulus.
- Rollback memulihkan keadaan.
- Evidence tidak menyimpan token/password/flag sensitif.
- Semua test reproducible dari clean checkout.

## Jadwal harian 60–90 menit

```text
10 menit  baca teori dan threat model
20 menit  observe/recon lab
25 menit  reproduce attack
20 menit  patch + regression
10 menit  tulis evidence dan lesson learned
5 menit   update mastery tracker
```

Satu sesi hanya satu teknik. Jangan mengejar banyak CVE sekaligus.

## Mastery rubric

- L1: bisa menjelaskan istilah dan menjalankan command aman.
- L2: bisa reproduce bug di fixture dengan panduan.
- L3: bisa membuat PoC dan patch sendiri.
- L4: bisa menggabungkan attack, defense, monitoring, SLA, dan evidence dalam batas waktu.

Tandai setiap topic dengan `L1/L2/L3/L4`, link ke lab, dan catat failure mode. Jangan naik level karena exploit berhasil saja; level naik setelah patch dan regression juga berhasil.

## Sumber yang dipakai

- GZCTF A&D fork documentation: `https://dimasc.tf/GZCTF/guide/`
- GZCTF upstream: `https://github.com/GZTimeWalker/GZCTF`
- TCP1P A&D testing repository: `https://github.com/TCP1P/TCP1PADTesting`
- LKS 2024/2025 kisi-kisi dari pengguna; detail kompetisi aktual tetap harus dikonfirmasi dari penyelenggara.

Catatan: fitur dan endpoint GZCTF fork dapat berbeda dari upstream. Selalu cek event rules, challenge manifest, checker, dan API resmi sebelum membuat adapter live.
