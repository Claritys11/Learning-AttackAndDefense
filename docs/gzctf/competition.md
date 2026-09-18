# GZCTF Competition Operations Guide

This guide details the operational procedures for competing in an A&D tournament running on GZCTF (such as `jjz.jatimprov.go.id`).

## 1. Network & WireGuard Setup
1. **Config Download**: Obtain your team WireGuard config (`wg0.conf`) from the competition dashboard.
2. **Bring up Tunnel**:
   ```bash
   sudo wg-quick up wg0
   ```
3. **Verify Tunnel & Interface**:
   ```bash
   sudo wg show
   ip addr show wg0
   ```
4. **Subnet Scope**: Identify your team's assigned IP address and the enemy subnet CIDRs.

## 2. VM Access & Service Inspection
1. **SSH Key Connection**:
   ```bash
   ssh -i ~/.ssh/id_rsa -p 22 <user>@<team_vm_ip>
   ```
2. **Initial Baseline Triage**:
   - List active services: `systemctl list-units --type=service` or `docker ps`.
   - List listening ports: `ss -tulpn`.
   - Find challenge directories: `/var/www`, `/opt`, or home directory.
   - Immediate backup: Copy critical challenge directories to a safe local backup.

## 3. Flag Lifecycle & Submission
1. In GZCTF, flags rotate every tick (typically 1-5 minutes).
2. Never accumulate stolen flags. Submit them via your automated script or console immediately upon capture to avoid the expiration window (`AdFlagLifetimeTicks`).

## 4. Rules & Compliance
- **No Denial of Service**: Attacking the platform scoreboard, WireGuard gateway, or saturating bandwidth is strictly against tournament rules.
- **Independence**: Strict anti-collusion policies apply; sharing flags or credentials across teams leads to immediate disqualification.
- **AI Policy**: Free tier web-based AI tools (ChatGPT, Claude, Gemini, DeepSeek) are permitted under tournament guidelines for assistance.
