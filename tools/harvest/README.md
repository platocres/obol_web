# OBOL QA Possibility-Space Harvester (`obol-harvest.sh`)

`obol-harvest.sh` is a private QA telemetry harvester (automatically stripped from `prod` by `publish.mjs`).

While user-facing **Cruise** (`assets/engine/cruise.js`) generates lean, stage-disciplined operator scripts for a single stage at a time, `obol-harvest.sh` is designed to probe a lab environment across the **full possibility space** (competing CLI tools per protocol, invalid-credential/404/403 failure baselines, self-chaining hash resolution, authenticated protocol sweeps, on-host triage, and internal subnet/pivot discovery) and capture everything into a single Markdown + `OBOL STEP` document.

## Usage on Kali

```bash
chmod +x obol-harvest.sh

# 1. Cold run against a single host (auto-discovers LHOST, ports, domain, users, and credentials):
./obol-harvest.sh 10.10.10.161

# 2. Multi-host / CIDR subnet sweep (auto-discovers live hosts and harvests each in sequence):
./obol-harvest.sh 10.10.110.0/24

# 3. Re-run with known credentials or NTLM hash:
./obol-harvest.sh 10.10.10.161 -u svc-alfresco -p s3rvice -d htb.local
./obol-harvest.sh 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -d htb.local

# 4. Pivot / internal subnet run over SOCKS proxy (proxychains4 / ligolo / chisel / ssh -D):
./obol-harvest.sh 172.16.5.0/24 --proxy -u svc-alfresco -p s3rvice -d htb.local
```

## Output

Running `obol-harvest.sh` produces:
1. **`harvest-<target>-<timestamp>.md`**: A single, self-contained Markdown document containing:
   - Every command's raw stdout/stderr fenced with `===== OBOL STEP N: <actionId> <command> <target> =====`
   - Exit codes, elapsed time, and line counts per step
   - **Wave 5 Internal Subnet & Pivot Neighbor Discovery** (secondary NICs, routes, ARP neighbors, and next-hop `--proxy` commands)
   - A full **Harvest Execution Index** table at the bottom
   - Ready-to-paste **On-Host Triage One-Liners**
2. **`harvest-work/<target>-<timestamp>/`**: Raw Nmap XML/gnmap files, `john.pot`, BloodHound `.zip` archives, and staged `www/onhost-linux.sh`.
