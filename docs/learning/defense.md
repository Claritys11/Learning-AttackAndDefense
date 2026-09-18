# Defense and SLA

## Objective
Patch root cause while preserving the checker-visible normal flow.

## Loop
`baseline -> minimal patch -> health -> normal flow -> replay exploit -> regression -> rollback`.

## Practice
Prefer validation, safe APIs, canonicalization, authorization at the server boundary, least privilege, and explicit configuration.

## Lab mapping
All runnable labs must provide a defense gate; start with [Command Injection](../../labs/02-command-injection/README.md).
