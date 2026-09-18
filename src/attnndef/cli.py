"""Composable CLI.

Each subcommand is a thin wrapper calling into the library modules -- no
business logic lives here. `solve` needs a caller-supplied attack
function; since this design must not invent exploit code, it is resolved
via `--attack-fn module:function` (dotted import path), and must exist in
the user's own project.

NOTE (UNKNOWN, do not fabricate): `submit` only writes an evidence record
locally with kind="submission". No GZCTF (or any platform) submission API
call is implemented, because its exact endpoint/schema was not given and
must not be guessed.
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
from .defense.health import HealthChecker
from .defense.patcher import TextReplacePatch
from .defense.replay import ExploitReplay
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
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="list targets from local registry")
    d.add_argument("--role", choices=[r.value for r in Role])
    d.add_argument("--tag", action="append", default=[])

    s = sub.add_parser("solve", help="run attack_fn against targets (bounded concurrency)")
    s.add_argument("--attack-fn", required=True, help="module:function")
    s.add_argument("--role", default="enemy")
    s.add_argument("--max-workers", type=int, default=4)
    s.add_argument("--timeout", type=float, default=10.0)

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

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
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

    return 1


if __name__ == "__main__":
    sys.exit(main())
