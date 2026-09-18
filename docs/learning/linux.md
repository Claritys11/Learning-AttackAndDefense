# Linux and administration

## Objective
Operate a Linux service safely: users, groups, permissions, processes, packages, logs, and services.

## Mental model
Identity + permission + process + file + network listener determine what a service can do.

## Practice
Use `id`, `sudo -l`, `ps`, `ss -lntup`, `lsof`, `find`, `stat`, `journalctl`, and `systemctl` only on your lab or owned host.

## Lab mapping
[Enumeration](../../labs/01-enumeration/README.md), [Mini A&D](../../labs/05-mini-ad/README.md).

## Mastery
L1 explain user/group/mode bits; L2 map a local service; L3 harden least privilege; L4 preserve SLA and prove rollback.
