# Attack & Defense Competition Overview

## Format & Objectives
In an Attack & Defense (A&D) competition, each participating team receives an identical virtual machine running several networked services. These services contain deliberate security vulnerabilities.

The match is organized into continuous rounds (or ticks), usually lasting 1 to 5 minutes each. During every tick:
- The scoring engine places a new, secret flag into every team's service instances.
- Teams attack enemy services to steal those flags and submit them for points.
- Teams defend their own services by analyzing code, patching vulnerabilities, and monitoring attacks.
- Automated SLA checkers verify that all services remain online and behave as expected.

## Competition Realities
- **Fast Paced**: Decisions must be made in seconds or minutes.
- **Dynamic Flags**: Flags rotate every round and expire after a short window (e.g. 3-5 rounds).
- **SLA Constraint**: A non-functional or disabled service causes rapid SLA point loss, which can lose the game faster than getting hacked.
- **Rule Compliance**: Infrastructure DoS, attacking game networks outside scope, or sharing flags between teams is strictly prohibited.
