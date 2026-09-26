/*!
 * obol ui — factpick.js — the guided "add a fact" picker.
 * A curated, plain-language catalogue of the facts an operator commonly needs to assert by hand
 * (when they did something obol's parsers can't derive), grouped by attack-chain phase with a
 * one-line description each — plus an "advanced: raw kind" escape hatch for power users. Both the
 * sidebar Facts panel and the Evidence route mount this. Manually-added facts are stored exactly
 * like parsed ones (source: 'manual'); they gate the methodology the same way.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  // kind, label (plain language), desc (one line). needPort → prompt for a port number → port:N.
  var CATALOG = [
    { phase: 'recon', label: 'Recon', items: [
      { kind: 'host.up', label: 'Host is up', desc: 'The target is alive / responds to a scan.' },
      { kind: 'port:__', label: 'A specific port is open…', desc: 'Mark one TCP port open (you pick the number).', needPort: true },
      { kind: 'ports.open', label: 'Open ports found (any)', desc: 'At least one open port was discovered.' },
    ] },
    { phase: 'enum', label: 'Enumeration', items: [
      { kind: 'http.reachable', label: 'Web server reachable (HTTP/S)', desc: 'A website/HTTP service responds.' },
      { kind: 'smb.reachable', label: 'SMB reachable (445)', desc: 'SMB / file shares are accessible.' },
      { kind: 'ldap.reachable', label: 'LDAP reachable (389)', desc: 'LDAP directory is accessible.' },
      { kind: 'kerberos.reachable', label: 'Kerberos reachable (88)', desc: 'Kerberos (AD auth) is accessible.' },
      { kind: 'rdp.reachable', label: 'RDP reachable (3389)', desc: 'Remote Desktop is accessible.' },
      { kind: 'ssh.reachable', label: 'SSH reachable (22)', desc: 'SSH is accessible.' },
      { kind: 'ad.domain_known', label: 'AD domain identified', desc: "You know the Active Directory domain name." },
    ] },
    { phase: 'creds', label: 'Credentials', items: [
      { kind: 'credential.candidate', label: 'Found a credential (unverified)', desc: "A username/password you haven't confirmed works yet." },
      { kind: 'credential.available', label: 'Valid credential (confirmed)', desc: 'A username/password proven to authenticate.' },
      { kind: 'hash.ntlm', label: 'Got an NTLM hash', desc: 'An NT hash you can spray / crack / pass.' },
      { kind: 'hash.asrep', label: 'Got an AS-REP hash', desc: 'A roastable AS-REP hash (crack offline).' },
      { kind: 'hash.tgs', label: 'Got a Kerberoast (TGS) hash', desc: 'A service-account TGS hash (crack offline).' },
    ] },
    { phase: 'access', label: 'Access / Foothold', items: [
      { kind: 'foothold.linux', label: 'Shell / foothold (Linux)', desc: 'You have code execution on a Linux target.' },
      { kind: 'foothold.windows', label: 'Shell / foothold (Windows)', desc: 'You have code execution on a Windows target.' },
      { kind: 'access.shell', label: 'Interactive shell', desc: 'A live interactive shell on the target.' },
      { kind: 'winrm.authenticated', label: 'WinRM login works', desc: 'You can log in over WinRM (evil-winrm).' },
    ] },
    { phase: 'escalate', label: 'Privilege escalation', items: [
      { kind: 'privesc.leads', label: 'Privesc lead found', desc: 'A promising local privilege-escalation vector.' },
      { kind: 'access.admin', label: 'Admin / root access', desc: 'You have administrative privileges on the box.' },
      { kind: 'access.system', label: 'SYSTEM access', desc: 'You have NT AUTHORITY\\SYSTEM.' },
    ] },
    { phase: 'loot', label: 'Loot / Objectives', items: [
      { kind: 'objective.local_flag', label: 'Captured user/local flag', desc: 'You read local.txt / user.txt.' },
      { kind: 'objective.root_flag', label: 'Captured root/proof flag', desc: 'You read proof.txt / root.txt.' },
      { kind: 'loot.ntds', label: 'Dumped domain hashes (NTDS)', desc: 'You dumped NTDS.dit / the domain secrets.' },
    ] },
  ];

  function esc(s) { return OBOL.util ? OBOL.util.esc(s) : String(s == null ? '' : s); }

  function optionsHtml() {
    return CATALOG.map(function (g) {
      return '<optgroup label="' + esc(g.label) + '">' + g.items.map(function (it) {
        return '<option value="' + esc(it.kind) + '" data-desc="' + esc(it.desc) + '"' + (it.needPort ? ' data-port="1"' : '') + '>' + esc(it.label) + '</option>';
      }).join('') + '</optgroup>';
    }).join('');
  }

  // Build the picker into `container` and call addFact(kind) for each chosen/typed fact.
  function mount(container, addFact) {
    if (!container) return;
    container.innerHTML = '';
    var row = document.createElement('div'); row.className = 'fp-row';
    var sel = document.createElement('select'); sel.className = 'fp-sel';
    sel.innerHTML = '<option value="">add a fact…</option>' + optionsHtml();
    var addBtn = document.createElement('button'); addBtn.type = 'button'; addBtn.className = 'btn-mini fp-add'; addBtn.textContent = 'add';
    row.appendChild(sel); row.appendChild(addBtn);

    var desc = document.createElement('div'); desc.className = 'fp-desc';
    var adv = document.createElement('button'); adv.type = 'button'; adv.className = 'fp-adv'; adv.textContent = 'advanced: raw fact kind';
    var raw = document.createElement('div'); raw.className = 'fp-raw'; raw.hidden = true;
    var rawIn = document.createElement('input'); rawIn.className = 'fp-input'; rawIn.placeholder = 'fact kind, e.g. smb.reachable'; rawIn.setAttribute('autocomplete', 'off');
    var rawAdd = document.createElement('button'); rawAdd.type = 'button'; rawAdd.className = 'btn-mini'; rawAdd.textContent = 'add';
    raw.appendChild(rawIn); raw.appendChild(rawAdd);

    function syncDesc() { var o = sel.options[sel.selectedIndex]; desc.textContent = (o && o.getAttribute('data-desc')) || ''; }
    sel.addEventListener('change', syncDesc);
    function doAdd() {
      var o = sel.options[sel.selectedIndex]; var kind = sel.value; if (!kind) return;
      if (o && o.getAttribute('data-port')) {
        var p = prompt('Which port is open?', '445'); if (p == null) return;
        p = String(p).replace(/\D/g, ''); if (!p) return; kind = 'port:' + p;
      }
      addFact(kind); sel.value = ''; syncDesc();
    }
    addBtn.addEventListener('click', doAdd);
    adv.addEventListener('click', function () { raw.hidden = !raw.hidden; if (!raw.hidden) rawIn.focus(); });
    function rawDo() { var k = (rawIn.value || '').trim(); if (!k) return; addFact(k); rawIn.value = ''; }
    rawAdd.addEventListener('click', rawDo);
    rawIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') rawDo(); });

    container.appendChild(row); container.appendChild(desc); container.appendChild(adv); container.appendChild(raw);
  }

  OBOL.factpick = { CATALOG: CATALOG, optionsHtml: optionsHtml, mount: mount };
})(typeof globalThis !== 'undefined' ? globalThis : this);
