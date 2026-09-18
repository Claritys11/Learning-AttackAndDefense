# Operator Console

## Launch

After installing the project:

```bash
python -m pip install -e .
attnndef
```

If no profile exists, the first launch asks for:

- learning/local/competition mode;
- operator, team, and team ID;
- optional VPN interface and network ranges;
- optional platform and competition metadata.

Secrets are not collected as raw values. Store a credential reference or inject credentials through a later adapter.

## State

The default SQLite state file is:

```text
~/.attnndef/state.db
```

Use another location for a lab or test:

```bash
attnndef --state-db /tmp/attnndef-lab.db
```

The persistent context currently stores profile, team/network metadata, selected target/service, round, and session ID. It does not yet implement target CRUD or a competition API.

## Direct CLI compatibility

Existing non-interactive commands remain available:

```bash
attnndef discover --role enemy
attnndef solve --attack-fn package.module:function
attnndef wave --solver name=package.module:function
attnndef health --check-fn package.module:function
```

The interactive shell and direct commands share the same package and persistence boundary; the operator shell is the Phase 1 entry point, not a fake dashboard.

## Current boundary

Phase 1 provides a real first-run shell and persistent context. Targets, recon adapters, flag queues, defense workflows, monitoring, rounds, and competition adapters are subsequent vertical slices. Until those slices exist, the menu reports them as unavailable rather than claiming success.

Only use attack and discovery features against localhost fixtures, owned infrastructure, or an explicitly authorized competition scope.
