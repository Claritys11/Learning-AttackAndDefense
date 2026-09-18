# Lab 01 — Enumeration

Goal: build an asset and endpoint map before attempting an exploit.

Scope: localhost fixture only. This lab teaches observation, not internet scanning.

## Tasks

1. Identify the service port from the declared lab target.
2. Confirm the protocol and health endpoint.
3. Record HTTP methods, routes, parameters, status codes, and interesting headers.
4. Identify the process and local listening socket.
5. Write an endpoint map in your notebook.

## Suggested learning tools

- `curl` for manual HTTP requests.
- `ss -lntup` for local listeners.
- `ps`/`lsof` for process ownership.
- `rg` for source/config review.

## Hint ladder

- Hint 0: start from the target registry.
- Hint 1: a healthy service usually exposes a deterministic health behavior.
- Hint 2: compare responses for known and unknown paths.
- Hint 3: inspect methods and parameters, not only page titles.
- Hint 4: correlate the port with a process.
- Hint 5: produce `asset -> listener -> process -> route -> input`.

## Completion

- [ ] Asset map written.
- [ ] Endpoint map written.
- [ ] Normal behavior recorded.
- [ ] Evidence is redacted.
- [ ] No unauthorized host was contacted.

Next: use the map to select a source-review or web lab.