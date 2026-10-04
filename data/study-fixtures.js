/*!
 * obol data — study-fixtures.js — OBOL.STUDY_FIXTURES
 *
 * The one piece of the study cell that is NOT derivable from the packs: a representative sample of
 * what each move's output actually looks like, with the one line that matters ("signal") and a plain
 * teach note about why it matters. A static site can't read the parser test fixtures at runtime, so
 * these are embedded here — trimmed but faithful to the real fixtures in
 * tests/engine/fixtures/parser/outputs/ (and standard tool output).
 *
 * `situation` / `choices` / `coach` drive the "Your turn" retrieval-practice gear. The verdict for
 * each choice (correct / also-valid / locked) is computed in study.js from the real requires — only
 * the choice set and the nuance coaching live here.
 *
 * Milestone 1 scope: the AD vertical slice (ad-dc-identify → … → dcsync).
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.STUDY_FIXTURES = {

    'ad-dc-identify': {
      output: [
        'PORT    STATE SERVICE',
        '88/tcp  open  kerberos-sec',
        '389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: acme.internal)',
        '445/tcp open  microsoft-ds',
        '464/tcp open  kpasswd5',
      ].join('\n'),
      signal: 'Domain: acme.internal',
      teach: 'Kerberos (88) + LDAP (389) on one host is the fingerprint of a Domain Controller, and the LDAP banner leaks the domain name — that name is what every later AD command needs.',
      situation: 'A fresh scan shows 88, 389 and 445 open on one host, and the LDAP banner names a domain.',
      choices: ['ad-dc-identify', 'ad-anon-ldap-enum', 'asrep-roast', 'dcsync'],
      coach: {
        'ad-anon-ldap-enum': 'That is the right next step — but only once you have confirmed this is the DC and captured the domain name. First, name the target.',
        'asrep-roast': 'Roasting needs a user list you do not have yet. You are one step too early.',
        'dcsync': 'DCSync replicates every hash — it needs Domain Admin. This is the endgame, not the opening.',
      },
    },

    'ad-anon-ldap-enum': {
      output: [
        'SMB         172.16.9.10  445  DC01  [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:acme.internal)',
        'LDAP        172.16.9.10  389  DC01  [+] acme.internal\\ (anonymous bind)',
        'LDAP        172.16.9.10  389  DC01  Administrator',
        'LDAP        172.16.9.10  389  DC01  jbloggs',
        'LDAP        172.16.9.10  389  DC01  tgibson',
        'LDAP        172.16.9.10  389  DC01  svc_backup',
        'LDAP        172.16.9.10  389  DC01  pparker',
      ].join('\n'),
      signal: '(anonymous bind)',
      teach: 'The DC answered an unauthenticated LDAP query and handed back account names. That user list is the seed for every no-creds AD attack that follows — roasting and spraying both need it.',
      situation: 'You have confirmed the DC and the domain is acme.internal. You hold no credentials yet.',
      choices: ['ad-anon-ldap-enum', 'asrep-roast', 'password-spray', 'dcsync'],
      coach: {
        'asrep-roast': 'Roasting needs a user list first. Get the list, then roast.',
        'password-spray': 'Spraying also needs the user list first — same prerequisite.',
        'dcsync': 'Needs Domain Admin. Far too early.',
      },
    },

    'asrep-roast': {
      output: [
        '[*] Getting TGT for jbloggs',
        "[-] User jbloggs doesn't have UF_DONT_REQUIRE_PREAUTH set",
        '[*] Getting TGT for tgibson',
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7d9e1f2043546576879a0b1c2d3$5e7b9d1f3a5c…',
        '[*] Getting TGT for svc_backup',
      ].join('\n'),
      signal: '$krb5asrep$23$',
      teach: 'Most users return "doesn\'t have UF_DONT_REQUIRE_PREAUTH set" — a dead end. The $krb5asrep$23$ line is an account with pre-auth disabled, so you just captured its password hash to crack offline.',
      situation: 'Anonymous LDAP handed you a user list and the DC answers on 88. You still have no credentials.',
      choices: ['asrep-roast', 'password-spray', 'kerberoast', 'dcsync'],
      coach: {
        'password-spray': 'Also valid off the user list — but it puts failed logons on the wire and risks lockout. AS-REP roasting gets crackable material with zero auth attempts, so it is the quieter opening move.',
        'kerberoast': 'Kerberoasting needs valid credentials to request service tickets — you have none. AS-REP roasting is its no-creds cousin: same idea, but it targets pre-auth-disabled accounts you can ask for anonymously.',
        'dcsync': 'Needs Domain Admin replication rights. This is the endgame, not step one.',
      },
    },

    'crack-asrep': {
      output: [
        '$krb5asrep$23$tgibson@ACME.INTERNAL:a3b5c7d9…:Autumn2026!',
        '',
        'Session..........: hashcat',
        'Status...........: Cracked',
        'Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)',
        'Recovered........: 1/1 (100.00%) Digests',
      ].join('\n'),
      signal: ':Autumn2026!',
      teach: 'hashcat recovered the plaintext after the colon. The AS-REP hash was only *candidate* material; a cracked password is a *validated* credential you can now actually log in with.',
      situation: 'You captured a $krb5asrep$23$ hash for tgibson and copied it to your box.',
      choices: ['crack-asrep', 'password-spray', 'ad-acl-abuse', 'dcsync'],
      coach: {
        'password-spray': 'You could spray, but you are holding a hash that may crack into a real password in seconds. Cash the hash you have first.',
        'ad-acl-abuse': 'ACL abuse needs a mapped attack path (BloodHound) and usually a foothold credential — you are not there yet.',
        'dcsync': 'Still needs Domain Admin. One cracked user is not that.',
      },
    },

    'password-spray': {
      output: [
        '2026/09/17 10:41:02 >  Using KDC(s):  172.16.9.10:88',
        '2026/09/17 10:41:03 >  [+] VALID LOGIN:  pparker@acme.internal:Autumn2026!',
        '2026/09/17 10:41:05 >  Done! Tested 48 logins (1 successes) in 2.882 seconds',
      ].join('\n'),
      signal: '[+] VALID LOGIN:',
      teach: 'One shared password tried against the whole user list found a hit. Spraying is loud — note the lockout risk — but a single valid login is a domain foothold. Spray one password, never many per account.',
      situation: 'You have a user list and the DC. AS-REP returned nothing roastable, so you try one seasonal password against everyone.',
      choices: ['password-spray', 'asrep-roast', 'kerberoast', 'dcsync'],
      coach: {
        'asrep-roast': 'Worth trying first (it is quieter), but if it returned nothing roastable, a careful single-password spray is the reasonable next swing.',
        'kerberoast': 'Still needs valid creds — which is exactly what the spray is trying to get you. Spray first, then roast service accounts.',
        'dcsync': 'Needs Domain Admin. A sprayed low-priv login is not that.',
      },
    },

    'ad-acl-abuse': {
      output: [
        '[+] svc-audit successfully added to group Help Desk Operators',
        'distinguishedName: CN=Help Desk Operators,CN=Users,DC=acme,DC=internal',
        'ActiveDirectoryRights: GenericAll',
      ].join('\n'),
      signal: 'GenericAll',
      teach: 'BloodHound showed your account holds GenericAll over an object, and you exercised it — adding yourself to a privileged group. ACL abuse is how a low-priv foothold walks a control path toward Domain Admin.',
      situation: 'You have a valid domain credential and BloodHound mapped a control path: your user has GenericAll over a privileged group.',
      choices: ['ad-acl-abuse', 'kerberoast', 'dcsync', 'asrep-roast'],
      coach: {
        'kerberoast': 'Reasonable with creds in hand, but you are holding a direct control-path edge to privilege — walk the ACL path rather than gambling on a crackable service ticket.',
        'dcsync': 'The right *destination*, but you need the replication rights first. The ACL abuse is how you get them.',
        'asrep-roast': 'You are well past the no-creds opening now — you already have a credential and a path.',
      },
    },

    'dcsync': {
      output: [
        '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
        'acme.internal\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::',
        'acme.internal\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::',
      ].join('\n'),
      signal: 'krbtgt:502:',
      teach: 'With replication rights you asked the DC to hand over password hashes. The krbtgt hash is the crown jewel — it mints golden tickets, which is total, persistent domain compromise.',
      situation: 'An ACL path escalated you to a principal with domain replication rights.',
      choices: ['dcsync', 'ad-acl-abuse', 'kerberoast', 'password-spray'],
      coach: {
        'ad-acl-abuse': 'That was the *previous* step — the one that got you the replication rights. You are past it now.',
        'kerberoast': 'Why crack one service account when you can replicate every hash in the domain? You are beyond this.',
        'password-spray': 'Far beneath where you are now — you hold replication rights over the whole domain.',
      },
    },

  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
