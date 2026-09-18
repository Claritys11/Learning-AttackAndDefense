# Source review

## Objective
Find root causes without relying on payload memorization.

## Mental model
Trace `input -> validation -> transformation -> sink -> impact`; mark trust boundaries and authorization checks.

## Practice
Use `rg` to find process, file, SQL, template, deserialization, and auth sinks. Confirm data flow manually.

## Lab mapping
[Command Injection](../../labs/02-command-injection/README.md), [Path Traversal](../../labs/03-path-traversal/README.md).

## Mastery
Explain the vulnerable line, reachable preconditions, minimal fix, and preserved normal behavior.
