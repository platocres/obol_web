# TASK-04: Cruise CR3 Single-Script Self-Healing Pivot Orchestrator

**Target Workspace:** `e:\KaliFiles\obol\obol-site\qa`  
**Recommended Model Tier:** Gemini Flash / Cost-Effective Agent  
**House Style:** NEVER use em dashes (`—`) or en dashes (`–`) in any code, comments, or strings. Use commas, colons, parentheses, or hyphens (` - `).

---

## 1. Strict File Ownership

**You may ONLY edit:**
- `assets/engine/pivotkit.js`
- `assets/ui/pivotstation.js`
- `assets/engine/parsers/pivot.js`
- `data/parser-signatures.js` (only if adding a new emitted fact kind)
- `tests/engine/pivotkit-smoke.js`

**Do NOT edit:** `data/packs/*.json`, `assets/engine/pack.js`, or `assets/engine/report.js`.

---

## 2. Architecture & Spec Context

Currently, `assets/engine/pivotkit.js` (`lines 109-156`) emits a basic `localKit(transportId, ctx)` script that runs `sudo ip tuntap`, prints the on-host lines, and `exec`s the proxy server.
Per the approved **Cruise CR3 Pivot Orchestrator Specification**, we want to upgrade `localKit(transportId, ctx)` in `assets/engine/pivotkit.js` and its UI in `assets/ui/pivotstation.js` + parser in `assets/engine/parsers/pivot.js` with four defensive capabilities:

### 1. Runtime Self-Healing & Pre-Flight Checks in `localKit()` (`assets/engine/pivotkit.js`)
Enhance the generated Bash script in `localKit(transportId, ctx)` so that (while remaining `bash -n` valid and keeping all existing unit tests in `tests/engine/pivotkit-smoke.js` green):
- **VPN Drift Detection (`tun0`)**:
  ```bash
  LIVE_TUN=$(ip -4 -o addr show dev tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
  if [ -n "$LIVE_TUN" ] && [ "$LIVE_TUN" != "$LHOST" ] && [ "$LHOST" != "LHOST" ]; then
    echo "[*] VPN drift detected: updating LHOST from $LHOST to $LIVE_TUN"
    LHOST="$LIVE_TUN"
  fi
  ```
- **Local Subnet Clash Guard**:
  Before adding a route for `$SUBNET`, check if `$SUBNET` collides with a local non-tun interface route (`ip -4 route show "$SUBNET" | grep -v 'dev ligolo'`). If it clashes, print a clear `[!] Warning: $SUBNET overlaps a local interface route` advisory.
- **Upfront `sudo -v` Priming & Guaranteed Teardown Trap (`ligolo`)**:
  For `ligolo`, prime `sudo -v` upfront and register a `cleanup()` function on `trap cleanup EXIT INT TERM` that removes the route (`sudo ip route del "$SUBNET" dev ligolo 2>/dev/null || true`) and tears down the interface (`sudo ip link set ligolo down 2>/dev/null || true`) when the operator exits with `Ctrl+C`.
- **Isolated Proxychains Config (`chisel` & `ssh-dynamic`)**:
  When `t.proxychains` is true, emit a helper line that writes `./.obol-proxychains.conf` (`strict_chain`, `proxy_dns`, `[ProxyList]`, `socks5 127.0.0.1 1080`) so the operator can run `proxychains4 -f ./.obol-proxychains.conf <cmd>` without polluting `/etc/proxychains4.conf`.
- **Evidence Sync Token Output**:
  Before starting the server in the foreground, print the 1-line sync token:
  ```text
  [*] Copy and paste this line into Obol Evidence once connected:
      obol:fact:pivot_active | subnet=$SUBNET | via=<transportId> | host=$PIVOT
  ```

### 2. Parse the Sync Token in `assets/engine/parsers/pivot.js`
Inspect `assets/engine/parsers/pivot.js`. Add a recognizer for:
`/obol:fact:pivot_active\s*\|\s*subnet=([^\s|]+)\s*\|\s*via=([^\s|]+)\s*\|\s*host=([^\s|]+)/i`
When matched, mint:
- `tunnel.route` (with `{ subnet: m[1], via: m[2], host: m[3] }`) for `ligolo` / `sshuttle`
- `tunnel.socks` (with `{ subnet: m[1], via: m[2], host: m[3], port: 1080 }`) for `chisel` / `ssh-dynamic`
- `pivot.active` (with `{ subnet: m[1], via: m[2], host: m[3] }`)
(Verify all three kinds are already in `data/parser-signatures.js` under `pivot`; they already are!).
Also ensure `assets/engine/parsers/index.js` dispatches to `_parse_pivot_output` whenever `text` contains `obol:fact:pivot_active`.

### 3. Egress Port Selector & Advisory Badge in `assets/ui/pivotstation.js`
Inspect `assets/ui/pivotstation.js`:
- Add quick egress port chips (`11601`, `443`, `8443`, `80`, `53`) next to the port input so the operator can switch egress ports with one click when a firewall blocks non-standard ports.
- Include the operator advisory note: *"Run in a dedicated tmux pane or terminal tab: the script stays in the foreground to keep the tunnel alive and cleans up on Ctrl-C."*

---

## 3. Verification Checklist (Must All Pass Before Completion)

Update `tests/engine/pivotkit-smoke.js` to assert:
1. Every generated `localKit` still passes `bash -n` (when bash is available) and contains the `trap cleanup EXIT INT TERM` (for ligolo), VPN drift check, and `obol:fact:pivot_active` sync token.
2. Pasting `obol:fact:pivot_active | subnet=172.16.2.0/24 | via=ligolo | host=10.10.11.23` into `OBOL.parsers.parseActionOutput` mints `pivot.active` and `tunnel.route`.

Run from `e:\KaliFiles\obol\obol-site\qa`:
```powershell
node tests/engine/pivotkit-smoke.js
node tools/gap-report.js --check
node tools/post-parse-audit.js --check
node tools/lint-study.js --check
node tools/stamp-assets.js
```
All commands must exit with code `0`.
