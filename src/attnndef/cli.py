"""Composable CLI.

Each subcommand is a thin wrapper calling into the library modules -- no
business logic lives here. `solve` needs a caller-supplied attack
function; since this design must not invent exploit code, it is resolved
via `--attack-fn module:function` (dotted import path), and must exist in
the user's own project.

The `wave` command orchestrates multiple approved solvers and can call an
explicitly configured HTTPS/localhost submission endpoint. It is dry-run
unless `--live-submit` is supplied.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
import time

from .attack.extractor import RegexExtractor
from .attack.runner import AttackRunner
from .core.models import Evidence, Role
from .core.registry import TargetRegistry
from .context import ContextStore
from .defense.health import HealthChecker
from .defense.patcher import TextReplacePatch
from .defense.replay import ExploitReplay
from .integrations.tool_runner import ToolRunner
from .io.logging_setup import setup_logging
from .io.sink import LocalSink


def _import_dotted(path: str):
    mod_name, _, attr = path.partition(":")
    if not attr:
        raise SystemExit(f"expected 'module:function', got {path!r}")
    mod = importlib.import_module(mod_name)
    return getattr(mod, attr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="attnndef")
    p.add_argument("--registry", default="config/targets.json")
    p.add_argument("--sink", default="evidence/evidence.jsonl")
    p.add_argument("--state-db", default="~/.attnndef/state.db")
    p.add_argument("--debug", action="store_true")
    sub = p.add_subparsers(dest="command")

    d = sub.add_parser("discover", help="list targets from local registry")
    d.add_argument("--role", choices=[r.value for r in Role])
    d.add_argument("--tag", action="append", default=[])

    s = sub.add_parser("solve", help="run attack_fn against targets (bounded concurrency)")
    s.add_argument("--attack-fn", required=True, help="module:function")
    s.add_argument("--role", default="enemy")
    s.add_argument("--max-workers", type=int, default=4)
    s.add_argument("--timeout", type=float, default=10.0)

    w = sub.add_parser("wave", help="run configured solvers and optional explicit submitter")
    w.add_argument("--solver", action="append", required=True, help="name=module:function")
    w.add_argument("--endpoint", help="exact verified submit endpoint")
    w.add_argument("--token-env", default="ATTNDEF_SUBMIT_TOKEN")
    w.add_argument("--live-submit", action="store_true", help="explicitly enable submission")
    w.add_argument("--max-workers", type=int, default=4)
    w.add_argument("--timeout", type=float, default=8.0)

    e = sub.add_parser("extract", help="extract flags from a raw-output file")
    e.add_argument("--input", required=True)
    e.add_argument("--target-id", required=True)

    sub_submit = sub.add_parser("submit", help="record a flag as submitted (local only)")
    sub_submit.add_argument("--target-id", required=True)
    sub_submit.add_argument("--flag", required=True)

    pa = sub.add_parser("patch", help="dry-run or apply a patch against own targets")
    pa.add_argument("--target-id", required=True)
    pa.add_argument("--search", required=True)
    pa.add_argument("--replace", required=True)
    pa.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")

    h = sub.add_parser("health", help="health-check own targets")
    h.add_argument("--check-fn", required=True, help="module:function")
    h.add_argument("--role", default="own")

    r = sub.add_parser("replay", help="regression test: exploit should fail, service should be healthy")
    r.add_argument("--target-id", required=True)
    r.add_argument("--attack-fn", required=True)
    r.add_argument("--check-fn", required=True)

    rb = sub.add_parser("rollback", help="restore the most recent backup for a target")
    rb.add_argument("--target-id", required=True)
    rb.add_argument("--backup-path", required=True)
    rb.add_argument("--config-path", required=True)

    # Tool Subcommands (Direct CLI parity)
    pn = sub.add_parser("nmap", help="run scoped nmap scan or discovery")
    pn.add_argument("--host", help="target host or IP")
    pn.add_argument("--ports", default="1-1024", help="ports range or list")
    pn.add_argument("--service-detection", action="store_true", help="enable -sV -sC")
    pn.add_argument("--discover", help="network CIDR for host discovery (-sn)")
    pn.add_argument("--timeout", type=float, default=30.0)
    pn.add_argument("--json", action="store_true")

    phttp = sub.add_parser("http", help="perform typed HTTP inspection request")
    phttp.add_argument("--url", required=True, help="target URL")
    phttp.add_argument("--method", default="GET", choices=["GET", "POST", "HEAD", "PUT", "DELETE"])
    phttp.add_argument("--header", action="append", default=[], help="custom header (Key: Value)")
    phttp.add_argument("--body", default=None, help="request body")
    phttp.add_argument("--timeout", type=float, default=10.0)
    phttp.add_argument("--json", action="store_true")

    pf = sub.add_parser("ffuf", help="run bounded endpoint fuzzing")
    pf.add_argument("--url", required=True, help="URL with FUZZ keyword")
    pf.add_argument("--wordlist", required=True, help="wordlist file path")
    pf.add_argument("--extension", action="append", default=[], help="extensions to append")
    pf.add_argument("--timeout", type=float, default=30.0)
    pf.add_argument("--json", action="store_true")

    pssh = sub.add_parser("ssh", help="run bounded non-interactive diagnostic command over SSH")
    pssh.add_argument("--host", required=True, help="SSH target host")
    pssh.add_argument("--command", "--cmd", dest="remote_command", required=True, help="remote diagnostic command")
    pssh.add_argument("--port", type=int, default=22)
    pssh.add_argument("--user", default="root")
    pssh.add_argument("--key", default=None, help="identity key file")
    pssh.add_argument("--timeout", type=float, default=15.0)
    pssh.add_argument("--json", action="store_true")

    ptcp = sub.add_parser("tcpdump", help="run bounded packet capture")
    ptcp.add_argument("--interface", default="any")
    ptcp.add_argument("--duration", type=float, default=5.0)
    ptcp.add_argument("--count", type=int, default=50)
    ptcp.add_argument("--filter", default="", help="BPF filter")
    ptcp.add_argument("--pcap", default=None, help="output pcap path")
    ptcp.add_argument("--json", action="store_true")

    pgdb = sub.add_parser("gdb", help="run batch non-interactive binary inspection with GDB")
    pgdb.add_argument("--binary", required=True, help="target binary path")
    pgdb.add_argument("--op", choices=["inspect", "crash", "registers", "memory"], default="inspect")
    pgdb.add_argument("--core", default=None, help="core dump path")
    pgdb.add_argument("--sym", default="main", help="symbol or address for memory inspection")
    pgdb.add_argument("--timeout", type=float, default=15.0)
    pgdb.add_argument("--json", action="store_true")

    psys = sub.add_parser("sys", help="run typed Linux system diagnostics")
    psys.add_argument("--op", choices=["ss-listen", "ss-all", "ps", "service", "ip-addr", "ip-route", "dig", "wg"], required=True)
    psys.add_argument("--name", default="", help="service name for service op")
    psys.add_argument("--domain", default="jjz.jatimprov.go.id", help="domain for dig op")
    psys.add_argument("--interface", default=None, help="interface for wg op")
    psys.add_argument("--json", action="store_true")

    # Operational Core Subcommands
    prnd = sub.add_parser("round", help="manage local round tracking and ticks")
    prnd.add_argument("--set", type=int, dest="round_number", help="start or set active round number")
    prnd.add_argument("--complete", action="store_true", help="complete the active round")
    prnd.add_argument("--tick", type=int, help="record local tick observation")
    prnd.add_argument("--list", action="store_true", help="list recorded rounds")
    prnd.add_argument("--json", action="store_true")

    pact = sub.add_parser("action", help="record or list operator actions")
    pact.add_argument("--record", action="store_true", help="record an action")
    pact.add_argument("--category", choices=["recon", "attack", "defense", "flag", "verification", "system"], default="recon")
    pact.add_argument("--target", default=None, help="target ID")
    pact.add_argument("--tool", default="manual")
    pact.add_argument("--op", default="action")
    pact.add_argument("--summary", default="", help="action summary")
    pact.add_argument("--status", default="completed")
    pact.add_argument("--round", type=int, default=None)
    pact.add_argument("--workflow", default=None, help="workflow ID to associate action with")
    pact.add_argument("--parent", "--parent-action", dest="parent_action_id", default=None, help="parent action ID (e.g. for defense verification)")
    pact.add_argument("--tool-exec", dest="tool_execution_id", default=None, help="tool execution ID")
    pact.add_argument("--mission", default=None, help="mission ID to associate action with")
    pact.add_argument("--list", action="store_true")
    pact.add_argument("--json", action="store_true")

    patk = sub.add_parser("attack", help="record, update, or list attack records")
    patk.add_argument("--record", action="store_true", help="record a new attack")
    patk.add_argument("--target", default=None, help="target ID")
    patk.add_argument("--service", default="http/80")
    patk.add_argument("--method", default="", help="attack / exploit method")
    patk.add_argument("--status", choices=["planned", "in_progress", "success", "failed", "aborted"], default="planned")
    patk.add_argument("--notes", default="")
    patk.add_argument("--workflow", default=None, help="workflow ID to associate attack with")
    patk.add_argument("--mission", default=None, help="mission ID to associate attack with")
    patk.add_argument("--update", dest="update_id", default=None, help="attack ID to update")
    patk.add_argument("--round", type=int, default=None)
    patk.add_argument("--list", action="store_true")
    patk.add_argument("--json", action="store_true")

    pdf = sub.add_parser("defense", help="record, update, or list defense records")
    pdf.add_argument("--record", action="store_true", help="record a new defense")
    pdf.add_argument("--target", default=None, help="target ID")
    pdf.add_argument("--service", default="http/80")
    pdf.add_argument("--action", dest="defense_action", default="", help="remediation action")
    pdf.add_argument("--status", choices=["planned", "in_progress", "completed", "failed", "reverted"], default="planned")
    pdf.add_argument("--notes", default="")
    pdf.add_argument("--workflow", default=None, help="workflow ID to associate defense with")
    pdf.add_argument("--mission", default=None, help="mission ID to associate defense with")
    pdf.add_argument("--update", dest="update_id", default=None, help="defense ID to update")
    pdf.add_argument("--round", type=int, default=None)
    pdf.add_argument("--list", action="store_true")
    pdf.add_argument("--json", action="store_true")

    pfl = sub.add_parser("flag", help="record, update, or list flag records (fingerprint only, no plaintext stored)")
    pfl.add_argument("--record", dest="raw_flag", default=None, help="flag string (automatically converted to sha256 fingerprint)")
    pfl.add_argument("--target", default=None, help="target ID")
    pfl.add_argument("--source", default="manual", help="flag source")
    pfl.add_argument("--status", choices=["observed", "validated", "submitted", "rejected", "expired"], default="observed")
    pfl.add_argument("--notes", default="")
    pfl.add_argument("--workflow", default=None, help="workflow ID to associate flag with")
    pfl.add_argument("--mission", default=None, help="mission ID to associate flag with")
    pfl.add_argument("--update", dest="update_id", default=None, help="flag ID to update")
    pfl.add_argument("--round", type=int, default=None)
    pfl.add_argument("--list", action="store_true")
    pfl.add_argument("--json", action="store_true")

    psla = sub.add_parser("sla", help="record or list local SLA observations")
    psla.add_argument("--record", action="store_true", help="record SLA observation")
    psla.add_argument("--target", default=None, help="target ID")
    psla.add_argument("--service", default="http/80")
    psla.add_argument("--status", choices=["ok", "mumble", "offline", "unknown"], default="ok")
    psla.add_argument("--latency", type=float, default=None, help="observed latency in ms")
    psla.add_argument("--source", default="local")
    psla.add_argument("--workflow", default=None, help="workflow ID to associate SLA observation with")
    psla.add_argument("--mission", default=None, help="mission ID to associate SLA observation with")
    psla.add_argument("--round", type=int, default=None)
    psla.add_argument("--list", action="store_true")
    psla.add_argument("--json", action="store_true")

    ptl = sub.add_parser("timeline", help="display chronological activity timeline")
    ptl.add_argument("--round", type=int, default=None)
    ptl.add_argument("--target", default=None)
    ptl.add_argument("--workflow", default=None, help="filter timeline by workflow ID")
    ptl.add_argument("--mission", default=None, help="filter timeline by mission ID")
    ptl.add_argument("--limit", type=int, default=50)
    ptl.add_argument("--json", action="store_true")

    pwf = sub.add_parser("workflow", help="create, manage, or list operator workflows")
    pwf.add_argument("--create", action="store_true", help="create a new workflow")
    pwf.add_argument("--title", default="", help="workflow title")
    pwf.add_argument("--objective", default="", help="workflow objective")
    pwf.add_argument("--target", default=None, help="target ID (optional)")
    pwf.add_argument("--notes", default="", help="workflow notes")
    pwf.add_argument("--round", type=int, default=None, help="round number")
    pwf.add_argument("--list", action="store_true", help="list workflows")
    pwf.add_argument("--status", choices=["active", "completed", "aborted"], default=None, help="filter by status")
    pwf.add_argument("--show", default=None, help="workflow ID to show")
    pwf.add_argument("--complete", default=None, help="workflow ID to complete")
    pwf.add_argument("--abort", default=None, help="workflow ID to abort")
    pwf.add_argument("--timeline", default=None, help="show timeline for workflow ID")
    pwf.add_argument("--json", action="store_true")

    pm = sub.add_parser("mission", help="create, manage, or list operator missions")
    pm.add_argument("--create", action="store_true", help="create a new mission")
    pm.add_argument("--workflow", default=None, help="workflow ID")
    pm.add_argument("--target", default=None, help="target ID")
    pm.add_argument("--port", type=int, default=None, help="service port")
    pm.add_argument("--protocol", default="tcp", choices=["tcp", "udp"], help="service protocol")
    pm.add_argument("--title", default="", help="mission title")
    pm.add_argument("--objective", default="", help="mission objective")
    pm.add_argument("--notes", default="", help="mission notes")
    pm.add_argument("--observation-id", dest="observation_id", type=int, default=None, help="initial observation ID")
    pm.add_argument("--list", action="store_true", help="list missions")
    pm.add_argument("--status", choices=["open", "in_progress", "completed", "aborted"], default=None, help="filter by status")
    pm.add_argument("--show", default=None, help="mission ID to show")
    pm.add_argument("--start", default=None, help="mission ID to start")
    pm.add_argument("--complete", default=None, help="mission ID to complete")
    pm.add_argument("--abort", default=None, help="mission ID to abort")
    pm.add_argument("--timeline", default=None, help="show timeline for mission ID")
    pm.add_argument("--json", action="store_true")

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        from .ui import InteractiveConsole
        return InteractiveConsole(ContextStore(args.state_db)).run()
    log = setup_logging()
    sink = LocalSink(args.sink)
    registry = TargetRegistry.from_file(args.registry)

    if args.command == "discover":
        role = Role(args.role) if args.role else None
        targets = registry.filter(role=role, tags=args.tag)
        print(json.dumps([t.__dict__ for t in targets], default=str, indent=2))
        return 0

    if args.command == "solve":
        targets = registry.filter(role=Role(args.role))
        attack_fn = _import_dotted(args.attack_fn)
        runner = AttackRunner(
            attack_fn=attack_fn,
            extractor=RegexExtractor(),
            sink=sink,
            max_workers=args.max_workers,
            per_target_timeout_s=args.timeout,
        )
        results = runner.run(targets)
        for r in results:
            print(json.dumps({"target": r.target_id, "success": r.success, "flag": r.flag}))
        return 0

    if args.command == "wave":
        from .attack.controller import SolverSpec, WaveController
        from .attack.submitter import HttpSubmitter
        specs = []
        for raw in args.solver:
            name, path = raw.split("=", 1)
            specs.append(SolverSpec(name, path, (), args.max_workers, args.timeout))
        results, flags = WaveController(specs, sink).run(registry.filter(role=Role("enemy")))
        submissions = []
        if args.endpoint:
            submissions = HttpSubmitter(args.endpoint, args.token_env, live=args.live_submit).submit(flags)
        elif args.live_submit:
            raise SystemExit("--live-submit requires --endpoint")
        print(json.dumps({"results": [r.__dict__ for r in results], "flags_found": len(flags), "submissions": [s.__dict__ for s in submissions]}, default=str))
        return 0

    if args.command == "extract":
        raw = open(args.input, encoding="utf-8").read()
        flag = RegexExtractor().extract(raw)
        sink.write(
            Evidence(
                id=f"extract-{args.target_id}-{int(time.time())}",
                ts=time.time(),
                kind="extract",
                target_id=args.target_id,
                ok=flag is not None,
                payload={"flag": flag},
            )
        )
        print(flag or "")
        return 0 if flag else 1

    if args.command == "submit":
        # Local record only -- see module docstring: no platform API call.
        sink.write(
            Evidence(
                id=f"submit-{args.target_id}-{int(time.time())}",
                ts=time.time(),
                kind="submission",
                target_id=args.target_id,
                ok=True,
                payload={"flag": args.flag, "submitted_to_platform": False},
            )
        )
        log.warning("submit is local-only; no platform API is implemented")
        return 0

    if args.command == "patch":
        target = registry.get(args.target_id)
        patcher = TextReplacePatch("backups", args.search, args.replace, sink=sink)
        if args.mode == "dry-run":
            plan = patcher.dry_run(target)
        else:
            plan = patcher.apply(target)
        print(json.dumps(plan.__dict__, default=str, indent=2))
        return 0

    if args.command == "health":
        check_fn = _import_dotted(args.check_fn)
        checker = HealthChecker(check_fn=check_fn, sink=sink)
        targets = registry.filter(role=Role(args.role))
        for t in targets:
            res = checker.check(t)
            print(json.dumps(res.__dict__, default=str))
        return 0

    if args.command == "replay":
        target = registry.get(args.target_id)
        attack_fn = _import_dotted(args.attack_fn)
        check_fn = _import_dotted(args.check_fn)
        runner = AttackRunner(attack_fn=attack_fn, extractor=RegexExtractor(), sink=sink)
        checker = HealthChecker(check_fn=check_fn, sink=sink)
        replay = ExploitReplay(runner, checker, sink=sink)
        verdict = replay.verify(target)
        print(json.dumps(verdict.__dict__))
        return 0 if verdict.patch_confirmed else 1

    if args.command == "rollback":
        from pathlib import Path
        import shutil

        backup = Path(args.backup_path)
        if not backup.exists():
            log.error("backup not found: %s", backup)
            return 1
        shutil.copy2(backup, args.config_path)
        sink.write(
            Evidence(
                id=f"rollback-{args.target_id}-{int(time.time())}",
                ts=time.time(),
                kind="patch_rollback",
                target_id=args.target_id,
                ok=True,
                payload={"backup_path": str(backup)},
            )
        )
        return 0

    if args.command == "nmap":
        from .tools import NmapAdapter, NmapService
        runner = ToolRunner()
        svc = NmapService(NmapAdapter(runner))
        if args.discover:
            hosts = svc.discover(args.discover, timeout_s=args.timeout)
            if getattr(args, "json", False):
                print(json.dumps([h.__dict__ for h in hosts], default=str, indent=2))
            else:
                for h in hosts:
                    print(f"{h.host}\t{h.status}")
        elif args.host:
            services = svc.scan_target(args.host, ports=args.ports, service_detection=args.service_detection, timeout_s=args.timeout)
            if getattr(args, "json", False):
                print(json.dumps([s.__dict__ for s in services], default=str, indent=2))
            else:
                for s in services:
                    print(f"{s.port}/{s.protocol}\t{s.name}\t{s.version}".rstrip())
        else:
            raise SystemExit("nmap requires either --host or --discover")
        return 0

    if args.command == "http":
        from .tools import HttpAdapter, HttpService
        runner = ToolRunner()
        svc = HttpService(HttpAdapter(runner))
        hdrs = {}
        for h in (args.header or []):
            if ":" in h:
                k, v = h.split(":", 1)
                hdrs[k.strip()] = v.strip()
        resp = svc.request(args.url, method=args.method, headers=hdrs, body=args.body, timeout_s=args.timeout)
        if getattr(args, "json", False):
            print(json.dumps(resp.__dict__, default=str, indent=2))
        else:
            print(f"HTTP {resp.status_code} ({resp.duration_s:.3f}s)")
            print(resp.body)
        return 0 if resp.status_code > 0 else 1

    if args.command == "ffuf":
        from .tools import FfufAdapter, FfufService
        runner = ToolRunner()
        svc = FfufService(FfufAdapter(runner))
        res = svc.discover_endpoints(args.url, args.wordlist, extensions=args.extension, timeout_s=args.timeout)
        if getattr(args, "json", False):
            print(json.dumps({"matches": [m.__dict__ for m in res.matches], "duration_s": res.duration_s}, default=str, indent=2))
        else:
            for m in res.matches:
                print(f"[{m.status}]\tlen={m.length}\t{m.url}")
        return 0

    if args.command == "ssh":
        from .tools import SshAdapter, SshService
        runner = ToolRunner()
        svc = SshService(SshAdapter(runner))
        res = svc.run(args.host, args.remote_command, port=args.port, username=args.user, identity_file=args.key, timeout_s=args.timeout)
        if getattr(args, "json", False):
            print(json.dumps(res.__dict__, default=str, indent=2))
        else:
            sys.stdout.write(res.stdout)
            if res.stderr:
                sys.stderr.write(res.stderr)
        return res.returncode or 0

    if args.command == "tcpdump":
        from .tools import TcpdumpAdapter, TcpdumpService
        runner = ToolRunner()
        svc = TcpdumpService(TcpdumpAdapter(runner))
        res = svc.capture_live(interface=args.interface, duration_s=args.duration, packet_count=args.count, bpf_filter=args.filter, output_pcap=args.pcap)
        if getattr(args, "json", False):
            print(json.dumps(res.__dict__, default=str, indent=2))
        else:
            print(res.raw_output)
        return 0

    if args.command == "gdb":
        from .tools import GdbAdapter, GdbService
        runner = ToolRunner()
        svc = GdbService(GdbAdapter(runner))
        if args.op == "inspect":
            res = svc.inspect_binary(args.binary, timeout_s=args.timeout)
        elif args.op == "crash":
            res = svc.analyze_crash(args.binary, core_path=args.core, timeout_s=args.timeout)
        elif args.op == "registers":
            res = svc.inspect_registers(args.binary, core_path=args.core, timeout_s=args.timeout)
        else:
            res = svc.inspect_memory(args.binary, address_or_symbol=args.sym, core_path=args.core, timeout_s=args.timeout)
        if getattr(args, "json", False):
            print(json.dumps(res.__dict__, default=str, indent=2))
        else:
            print(res.stdout)
        return res.returncode or 0

    if args.command == "sys":
        from .tools import SystemAdapter, SystemService
        runner = ToolRunner()
        svc = SystemService(SystemAdapter(runner))
        if args.op == "ss-listen":
            res = svc.ss_listening()
        elif args.op == "ss-all":
            res = svc.ss_all()
        elif args.op == "ps":
            res = svc.ps_aux()
        elif args.op == "service":
            if not args.name:
                raise SystemExit("sys --op service requires --name <service>")
            res = svc.systemctl_status(args.name)
        elif args.op == "ip-addr":
            res = svc.ip_addr()
        elif args.op == "ip-route":
            res = svc.ip_route()
        elif args.op == "dig":
            res = svc.dig_lookup(args.domain)
        elif args.op == "wg":
            res = svc.wireguard_status(args.interface)
        if getattr(args, "json", False):
            print(json.dumps(res.__dict__, default=str, indent=2))
        else:
            print(res.stdout)
        return res.returncode or 0

    if args.command == "round":
        from .operations import OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        sid = ctx.session_id if ctx else "default-session"
        if args.round_number is not None:
            r = ops.start_round(sid, args.round_number)
            if ctx:
                ctx.current_round = args.round_number
                ContextStore(args.state_db).save(ctx)
            if getattr(args, "json", False):
                print(json.dumps(r.__dict__, default=str, indent=2))
            else:
                print(f"Round #{r.round_id} started ({r.status.value})")
            return 0
        elif args.complete:
            cur_rnd = ctx.current_round if ctx else 1
            ok = ops.complete_round(cur_rnd)
            if getattr(args, "json", False):
                print(json.dumps({"round_id": cur_rnd, "completed": ok}))
            else:
                print(f"Round #{cur_rnd} completed: {ok}")
            return 0
        elif args.tick is not None:
            cur_rnd = ctx.current_round if ctx else 1
            t = ops.record_tick(sid, cur_rnd, args.tick)
            if getattr(args, "json", False):
                print(json.dumps(t.__dict__, default=str, indent=2))
            else:
                print(f"Tick #{t.tick_number} recorded for round #{t.round_id}")
            return 0
        elif args.list or True:
            rounds = ops.list_rounds(sid)
            if getattr(args, "json", False):
                print(json.dumps([r.__dict__ for r in rounds], default=str, indent=2))
            else:
                for r in rounds:
                    print(f"Round #{r.round_number}\tStatus: {r.status.value}\tStarted: {r.started_at}")
            return 0

    if args.command == "action":
        from .operations import ActionCategory, OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        sid = ctx.session_id if ctx else "default-session"
        cur_rnd = args.round if args.round is not None else (ctx.current_round if ctx else 1)
        if args.record:
            cat = ActionCategory(args.category)
            act = ops.record_action(
                sid,
                cur_rnd,
                cat,
                args.tool,
                args.op,
                args.summary,
                target_id=args.target,
                status=args.status,
                workflow_id=getattr(args, "workflow", None),
                parent_action_id=getattr(args, "parent_action_id", None),
                tool_execution_id=getattr(args, "tool_execution_id", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps(act.__dict__, default=str, indent=2))
            else:
                wf_str = f" [WF: {act.workflow_id[:8]}]" if act.workflow_id else ""
                ms_str = f" [MS: {act.mission_id[:8]}]" if act.mission_id else ""
                print(f"Action [{act.category.value.upper()}]{wf_str}{ms_str} recorded: {act.summary} (ID: {act.id[:8]})")
            return 0
        else:
            actions = ops.list_actions(
                round_id=args.round,
                target_id=args.target,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps([a.__dict__ for a in actions], default=str, indent=2))
            else:
                for a in actions:
                    wf_str = f" [WF:{a.workflow_id[:8]}]" if a.workflow_id else ""
                    ms_str = f" [MS:{a.mission_id[:8]}]" if a.mission_id else ""
                    print(f"[{a.category.value.upper():<12}]\t{a.target_id or '-'}\t{a.summary}{wf_str}{ms_str}\t({a.status})")
            return 0

    if args.command == "attack":
        from .operations import AttackStatus, OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        cur_rnd = args.round if args.round is not None else (ctx.current_round if ctx else 1)
        if args.record:
            if not args.target:
                raise SystemExit("attack --record requires --target <target_id>")
            st = AttackStatus(args.status)
            atk = ops.record_attack(
                cur_rnd,
                args.target,
                args.service,
                args.method,
                status=st,
                notes=args.notes,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps(atk.__dict__, default=str, indent=2))
            else:
                wf_str = f" [WF: {atk.workflow_id[:8]}]" if atk.workflow_id else ""
                ms_str = f" [MS: {atk.mission_id[:8]}]" if atk.mission_id else ""
                print(f"Attack [{atk.id[:8]}]{wf_str}{ms_str} recorded against {atk.target_id} ({atk.status.value})")
            return 0
        elif args.update_id:
            st = AttackStatus(args.status)
            ok = ops.update_attack_status(args.update_id, st, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"id": args.update_id, "updated": ok, "status": st.value}))
            else:
                print(f"Attack [{args.update_id[:8]}] updated to {st.value}: {ok}")
            return 0
        else:
            attacks = ops.list_attacks(
                round_id=args.round,
                target_id=args.target,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps([a.__dict__ for a in attacks], default=str, indent=2))
            else:
                for a in attacks:
                    wf_str = f" [WF:{a.workflow_id[:8]}]" if a.workflow_id else ""
                    ms_str = f" [MS:{a.mission_id[:8]}]" if a.mission_id else ""
                    print(f"[{a.id[:8]}]\t{a.target_id}\t{a.service}\t{a.status.value}\t{a.method}{wf_str}{ms_str}")
            return 0

    if args.command == "defense":
        from .operations import DefenseStatus, OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        cur_rnd = args.round if args.round is not None else (ctx.current_round if ctx else 1)
        if args.record:
            if not args.target:
                raise SystemExit("defense --record requires --target <target_id>")
            st = DefenseStatus(args.status)
            df = ops.record_defense(
                cur_rnd,
                args.target,
                args.service,
                args.defense_action,
                status=st,
                notes=args.notes,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps(df.__dict__, default=str, indent=2))
            else:
                wf_str = f" [WF: {df.workflow_id[:8]}]" if df.workflow_id else ""
                ms_str = f" [MS: {df.mission_id[:8]}]" if df.mission_id else ""
                print(f"Defense [{df.id[:8]}]{wf_str}{ms_str} recorded for {df.target_id} ({df.status.value})")
            return 0
        elif args.update_id:
            st = DefenseStatus(args.status)
            ok = ops.update_defense_status(args.update_id, st, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"id": args.update_id, "updated": ok, "status": st.value}))
            else:
                print(f"Defense [{args.update_id[:8]}] updated to {st.value}: {ok}")
            return 0
        else:
            defenses = ops.list_defenses(
                round_id=args.round,
                target_id=args.target,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps([d.__dict__ for d in defenses], default=str, indent=2))
            else:
                for d in defenses:
                    wf_str = f" [WF:{d.workflow_id[:8]}]" if d.workflow_id else ""
                    ms_str = f" [MS:{d.mission_id[:8]}]" if d.mission_id else ""
                    print(f"[{d.id[:8]}]\t{d.target_id}\t{d.service}\t{d.status.value}\t{d.action}{wf_str}{ms_str}")
            return 0

    if args.command == "flag":
        from .operations import FlagStatus, OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        cur_rnd = args.round if args.round is not None else (ctx.current_round if ctx else 1)
        if args.raw_flag:
            if not args.target:
                raise SystemExit("flag --record requires --target <target_id>")
            st = FlagStatus(args.status)
            fl = ops.record_flag(
                cur_rnd,
                args.target,
                args.source,
                args.raw_flag,
                status=st,
                notes=args.notes,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps(fl.__dict__, default=str, indent=2))
            else:
                wf_str = f" [WF: {fl.workflow_id[:8]}]" if fl.workflow_id else ""
                ms_str = f" [MS: {fl.mission_id[:8]}]" if fl.mission_id else ""
                print(f"Flag [{fl.id[:8]}]{wf_str}{ms_str} recorded: {fl.flag_preview} (status: {fl.status.value})")
            return 0
        elif args.update_id:
            st = FlagStatus(args.status)
            ok = ops.update_flag_status(args.update_id, st, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"id": args.update_id, "updated": ok, "status": st.value}))
            else:
                print(f"Flag [{args.update_id[:8]}] updated to {st.value}: {ok}")
            return 0
        else:
            flags = ops.list_flags(
                round_id=args.round,
                target_id=args.target,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps([f.__dict__ for f in flags], default=str, indent=2))
            else:
                for f in flags:
                    wf_str = f" [WF:{f.workflow_id[:8]}]" if f.workflow_id else ""
                    ms_str = f" [MS:{f.mission_id[:8]}]" if f.mission_id else ""
                    print(f"[{f.id[:8]}]\t{f.target_id}\t{f.flag_preview}\t{f.status.value}\t{f.source}{wf_str}{ms_str}")
            return 0

    if args.command == "sla":
        from .operations import SlaStatus, OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        cur_rnd = args.round if args.round is not None else (ctx.current_round if ctx else 1)
        if args.record:
            if not args.target:
                raise SystemExit("sla --record requires --target <target_id>")
            st = SlaStatus(args.status)
            sla_rec = ops.record_sla(
                cur_rnd,
                args.target,
                args.service,
                st,
                latency_ms=args.latency,
                source=args.source,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps(sla_rec.__dict__, default=str, indent=2))
            else:
                lat = f"{sla_rec.latency_ms:.0f}ms" if sla_rec.latency_ms is not None else "n/a"
                wf_str = f" [WF: {sla_rec.workflow_id[:8]}]" if sla_rec.workflow_id else ""
                ms_str = f" [MS: {sla_rec.mission_id[:8]}]" if sla_rec.mission_id else ""
                print(f"SLA recorded{wf_str}{ms_str}: {sla_rec.target_id} {sla_rec.service} -> {sla_rec.status.value} ({lat})")
            return 0
        else:
            sla_list = ops.list_sla(
                round_id=args.round,
                target_id=args.target,
                workflow_id=getattr(args, "workflow", None),
                mission_id=getattr(args, "mission", None),
            )
            if getattr(args, "json", False):
                print(json.dumps([s.__dict__ for s in sla_list], default=str, indent=2))
            else:
                for s in sla_list:
                    lat = f"{s.latency_ms:.0f}ms" if s.latency_ms is not None else "n/a"
                    wf_str = f" [WF:{s.workflow_id[:8]}]" if s.workflow_id else ""
                    ms_str = f" [MS:{s.mission_id[:8]}]" if s.mission_id else ""
                    print(f"{s.target_id}\t{s.service}\t{s.status.value}\t{lat}\t({s.source}){wf_str}{ms_str}")
            return 0

    if args.command == "timeline":
        from .operations import OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ms_id = getattr(args, "mission", None)
        if ms_id:
            m = ops.get_mission(ms_id)
            if not m:
                raise SystemExit(f"Mission not found: {ms_id}")
            entries = ops.get_mission_timeline(ms_id, limit=args.limit)
            if getattr(args, "json", False):
                print(json.dumps([e.__dict__ for e in entries], default=str, indent=2))
            else:
                print(f"MISSION #{m.mission_id[:8]}")
                print(f"{m.title}")
                print(f"Target: {m.target_id}\tService: {m.service_protocol.upper()}:{m.service_port}")
                print(f"Status: {m.status.value.upper()}")
                print()
                if not entries:
                    print("(no activity recorded for this mission)")
                else:
                    print(f"{'TIME':<10}\t{'CATEGORY':<14}\t{'EVENT'}")
                    for e in entries:
                        t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                        print(f"{t_str:<10}\t{e.category:<14}\t{e.title}")
            return 0

        wf_id = getattr(args, "workflow", None)
        if wf_id:
            wf = ops.get_workflow(wf_id)
            if not wf:
                raise SystemExit(f"Workflow not found: {wf_id}")
            entries = ops.get_workflow_timeline(wf_id, limit=args.limit)
            if getattr(args, "json", False):
                print(json.dumps([e.__dict__ for e in entries], default=str, indent=2))
            else:
                print(f"WORKFLOW #{wf.workflow_id[:8]}")
                print(f"{wf.title}")
                print(f"Status: {wf.status.value.upper()}")
                print()
                if not entries:
                    print("(no activity recorded for this workflow)")
                else:
                    print(f"{'TIME':<10}\t{'CATEGORY':<14}\t{'EVENT'}")
                    for e in entries:
                        t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                        print(f"{t_str:<10}\t{e.category:<14}\t{e.title}")
            return 0

        entries = ops.get_timeline(round_id=args.round, target_id=args.target, limit=args.limit)
        if getattr(args, "json", False):
            print(json.dumps([e.__dict__ for e in entries], default=str, indent=2))
        else:
            if not entries:
                print("(no operational timeline entries found)")
            else:
                for e in entries:
                    t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                    tgt = f"{e.target_id:<14}" if e.target_id else " " * 14
                    print(f"{t_str}\t{e.category:<12}\t{tgt}\t{e.title}\t[{e.status}]")
        return 0

    if args.command == "workflow":
        from .operations import OperationService, WorkflowStatus
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))
        ctx = ContextStore(args.state_db).load()
        sid = ctx.session_id if ctx else "default-session"
        cur_rnd = args.round if args.round is not None else (ctx.current_round if ctx else 1)

        if args.create:
            if not args.title:
                raise SystemExit("workflow --create requires --title <title>")
            wf = ops.create_workflow(
                session_id=sid,
                round_id=cur_rnd,
                title=args.title,
                objective=args.objective or "",
                target_id=args.target,
                notes=args.notes or "",
            )
            if getattr(args, "json", False):
                print(json.dumps(wf.__dict__, default=str, indent=2))
            else:
                print(f"Workflow [{wf.workflow_id[:8]}] created: {wf.title} (Status: {wf.status.value})")
            return 0

        elif args.show:
            wf = ops.get_workflow(args.show)
            if not wf:
                raise SystemExit(f"Workflow not found: {args.show}")
            if getattr(args, "json", False):
                print(json.dumps(wf.__dict__, default=str, indent=2))
            else:
                print(f"WORKFLOW #{wf.workflow_id[:8]}")
                print(f"Title:     {wf.title}")
                print(f"Objective: {wf.objective or '-'}")
                print(f"Target:    {wf.target_id or '-'}")
                print(f"Status:    {wf.status.value.upper()}")
                print(f"Round:     #{wf.round_id}")
                if wf.notes:
                    print(f"Notes:     {wf.notes}")
            return 0

        elif args.complete:
            ok = ops.complete_workflow(args.complete, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"workflow_id": args.complete, "completed": ok, "status": "completed"}))
            else:
                print(f"Workflow [{args.complete[:8]}] completed: {ok}")
            return 0

        elif args.abort:
            ok = ops.abort_workflow(args.abort, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"workflow_id": args.abort, "aborted": ok, "status": "aborted"}))
            else:
                print(f"Workflow [{args.abort[:8]}] aborted: {ok}")
            return 0

        elif args.timeline:
            wf = ops.get_workflow(args.timeline)
            if not wf:
                raise SystemExit(f"Workflow not found: {args.timeline}")
            entries = ops.get_workflow_timeline(args.timeline)
            if getattr(args, "json", False):
                print(json.dumps([e.__dict__ for e in entries], default=str, indent=2))
            else:
                print(f"WORKFLOW #{wf.workflow_id[:8]}")
                print(f"{wf.title}")
                print(f"Status: {wf.status.value.upper()}")
                print()
                if not entries:
                    print("(no activity recorded for this workflow)")
                else:
                    print(f"{'TIME':<10}\t{'CATEGORY':<14}\t{'EVENT'}")
                    for e in entries:
                        t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                        print(f"{t_str:<10}\t{e.category:<14}\t{e.title}")
            return 0

        else:
            st = WorkflowStatus(args.status) if args.status else None
            workflows = ops.list_workflows(round_id=args.round, status=st, target_id=args.target)
            if getattr(args, "json", False):
                print(json.dumps([w.__dict__ for w in workflows], default=str, indent=2))
            else:
                if not workflows:
                    print("(no workflows found)")
                else:
                    for w in workflows:
                        tgt = f"[{w.target_id}]" if w.target_id else ""
                        print(f"[{w.workflow_id[:8]}]\t{w.status.value.upper():<10}\tR#{w.round_id}\t{tgt}\t{w.title}")
            return 0

    if args.command == "mission":
        from .operations import MissionStatus, OperationService
        from .targets import TargetService
        ops = OperationService(args.state_db, target_service=TargetService(args.state_db))

        if args.create:
            if not args.workflow or not args.target or args.port is None:
                raise SystemExit("mission --create requires --workflow <workflow_id> --target <target_id> --port <port>")
            m = ops.create_mission(
                workflow_id=args.workflow,
                target_id=args.target,
                service_port=args.port,
                title=args.title or f"Mission {args.target}:{args.port}",
                service_protocol=args.protocol or "tcp",
                objective=args.objective or "",
                notes=args.notes or "",
                initial_observation_id=args.observation_id,
            )
            if getattr(args, "json", False):
                print(json.dumps(m.__dict__, default=str, indent=2))
            else:
                print(f"Mission [{m.mission_id[:8]}] created: {m.title} (Status: {m.status.value})")
            return 0

        elif args.show:
            m = ops.get_mission(args.show)
            if not m:
                raise SystemExit(f"Mission not found: {args.show}")
            if getattr(args, "json", False):
                print(json.dumps(m.__dict__, default=str, indent=2))
            else:
                print(f"MISSION #{m.mission_id[:8]}")
                print(f"Title:     {m.title}")
                print(f"Workflow:  #{m.workflow_id[:8]}")
                print(f"Target:    {m.target_id}")
                print(f"Service:   {m.service_protocol.upper()}/{m.service_port}")
                print(f"Status:    {m.status.value.upper()}")
                print(f"Objective: {m.objective or '-'}")
                if m.initial_observation_id:
                    print(f"Init Obs:  #{m.initial_observation_id}")
                if m.notes:
                    print(f"Notes:     {m.notes}")
            return 0

        elif args.start:
            ok = ops.start_mission(args.start)
            if getattr(args, "json", False):
                print(json.dumps({"mission_id": args.start, "started": ok, "status": "in_progress"}))
            else:
                print(f"Mission [{args.start[:8]}] started: {ok}")
            return 0

        elif args.complete:
            ok = ops.complete_mission(args.complete, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"mission_id": args.complete, "completed": ok, "status": "completed"}))
            else:
                print(f"Mission [{args.complete[:8]}] completed: {ok}")
            return 0

        elif args.abort:
            ok = ops.abort_mission(args.abort, notes=args.notes or None)
            if getattr(args, "json", False):
                print(json.dumps({"mission_id": args.abort, "aborted": ok, "status": "aborted"}))
            else:
                print(f"Mission [{args.abort[:8]}] aborted: {ok}")
            return 0

        elif args.timeline:
            m = ops.get_mission(args.timeline)
            if not m:
                raise SystemExit(f"Mission not found: {args.timeline}")
            entries = ops.get_mission_timeline(args.timeline)
            if getattr(args, "json", False):
                print(json.dumps([e.__dict__ for e in entries], default=str, indent=2))
            else:
                print(f"MISSION #{m.mission_id[:8]}")
                print(f"{m.title}")
                print(f"Target: {m.target_id}\tService: {m.service_protocol.upper()}:{m.service_port}")
                print(f"Status: {m.status.value.upper()}")
                print()
                if not entries:
                    print("(no activity recorded for this mission)")
                else:
                    print(f"{'TIME':<10}\t{'CATEGORY':<14}\t{'EVENT'}")
                    for e in entries:
                        t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                        print(f"{t_str:<10}\t{e.category:<14}\t{e.title}")
            return 0

        else:
            st = MissionStatus(args.status) if args.status else None
            missions = ops.list_missions(workflow_id=args.workflow, target_id=args.target, status=st)
            if getattr(args, "json", False):
                print(json.dumps([m.__dict__ for m in missions], default=str, indent=2))
            else:
                if not missions:
                    print("(no missions found)")
                else:
                    for m in missions:
                        svc_str = f"{m.service_protocol.upper()}:{m.service_port}"
                        print(f"[{m.mission_id[:8]}]\t{m.status.value.upper():<12}\t[{m.target_id}]\t{svc_str:<10}\t{m.title}")
            return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
