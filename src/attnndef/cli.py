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

    return 1


if __name__ == "__main__":
    sys.exit(main())
