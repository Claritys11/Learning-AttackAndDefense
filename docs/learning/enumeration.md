# Enumeration

## Objective
Turn a target into an evidence-backed attack-surface map before exploiting it.

## Loop
`target -> ports -> service -> version -> routes -> methods -> parameters -> process -> hypotheses`.

## Practice
Start with `curl`, `ss`, `lsof`, `rg`, and only then use scoped scanners against declared fixtures.

## Lab mapping
[Lab 01](../../labs/01-enumeration/README.md).

## Mastery
L1 list assets; L2 produce a route map; L3 identify likely trust boundaries; L4 complete it under a timer with redacted evidence.
