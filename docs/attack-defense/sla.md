# Service Level Agreement (SLA) & Availability

## Why "Patched" Does Not Mean "Good Defense"

A common mistake in Attack & Defense is attempting defense through service destruction:
- Turning off the web server (`systemctl stop nginx`)
- Dropping all incoming packets with iptables (`iptables -A INPUT -j DROP`)
- Deleting the `/flag` file or setting permissions to `000`
- Returning HTTP 403 / 500 for all incoming requests

While this prevents opponents from stealing your flag via that service, it triggers an immediate **SLA Failure**:
1. The game platform's SLA checker polls every service on your VM every round.
2. If the checker cannot connect, receives an unexpected HTTP status, or fails to retrieve/plant its test token, your team receives **0 SLA points** for that round.
3. In modern A&D scoring (including GZCTF), SLA points frequently account for a decisive portion of the total match score. A team that loses SLA across multiple services will quickly drop to the bottom of the scoreboard.

## Safe Defense Principles
1. **Always backup** before modifying any source code or configuration.
2. **Surgical remediation**: Only modify the exact lines of code causing the flaw.
3. **Smoke testing**: Run a test client verifying standard user actions (login, post, view, fetch) before putting the patch into production.
4. **Service stability**: Ensure service processes restart cleanly under systemd or supervisor.
