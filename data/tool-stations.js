/*!
 * obol data — tool-stations.js — SUBSTITUTE tools grouped by the JOB they do.
 *
 * A station answers "I want to do X" (discover web content, crack these hashes, scan ports) and lets
 * the student pick the engine, with one line on why each exists. Switching engine keeps the shared
 * parameters (the wordlist, the ports) via each engine's sharedMap. This groups only SUBSTITUTES
 * (tools that do the same job): complements like smbclient vs smbmap stay separate cards. The default
 * engine can be fact-aware (whenFact). Presentation only: each engine is an existing Tool Builder, the
 * pack commands stay the source of truth. House style: no em or en dashes.
 *
 * `hue` names a lane CSS class (lane-web, lane-creds, lane-recon ...) for the station band colour.
 * `sharedParams` are the knobs carried across an engine swap; `sharedMap` maps each to that engine's
 * field id (omit when the field id is identical). Engines whose builder is not in the TOOLSET yet are
 * skipped by OBOL.toolkit.stationBuilders, so TC can append rustscan/masscan/db-shells here later.
 */
(function (root) {
  'use strict';
  var OBOL = root.OBOL = root.OBOL || {};

  OBOL.STATIONS = [
    {
      id: 'web-content',
      title: 'Web Content Discovery',
      job: 'Find hidden paths, files, and virtual hosts on a web server.',
      hue: 'web',
      sharedParams: ['wordlist', 'extensions'],
      defaultEngine: 'tb-ffuf',
      engines: [
        { builderId: 'tb-ffuf', tool: 'ffuf', label: 'ffuf', teach: 'Fastest, with the best noise filtering (-fs, -fc, -ac). The default pick.' },
        { builderId: 'tb-gobuster-ferox', tool: 'gobuster / feroxbuster', label: 'gobuster / feroxbuster', teach: 'Simple and dependable; feroxbuster auto-recurses into every folder it finds.' },
        { builderId: 'tb-wfuzz', tool: 'wfuzz', label: 'wfuzz', teach: 'Most flexible FUZZ placement: great for parameters and awkward vhost setups.' },
      ],
    },
    {
      id: 'crack-hashes',
      title: 'Crack Hashes',
      job: 'Recover plaintext passwords from captured hashes offline.',
      hue: 'creds',
      sharedParams: ['wordlist'],
      defaultEngine: 'tb-hashcat',
      engines: [
        { builderId: 'tb-hashcat', tool: 'hashcat', label: 'hashcat', teach: 'GPU-fast. You give it the -m mode number for the exact hash type.' },
        { builderId: 'tb-john', tool: 'john', label: 'john', teach: 'No GPU needed, names formats in words (krb5asrep). The CPU fallback.' },
      ],
    },
    {
      id: 'port-scan',
      title: 'Port Scan',
      job: 'Find which TCP and UDP ports are open, then what services run on them.',
      hue: 'recon',
      sharedParams: ['ports'],
      defaultEngine: 'tb-nmap',
      engines: [
        { builderId: 'tb-nmap', tool: 'nmap', label: 'nmap', teach: 'The reference scanner: discovery, versions, and NSE scripts all in one.' },
        { builderId: 'tb-rustscan', tool: 'rustscan', label: 'rustscan', teach: 'Finds open ports in seconds, then hands them straight to nmap for the service scan.' },
        { builderId: 'tb-masscan', tool: 'masscan', label: 'masscan', teach: 'Internet-scale speed for a wide sweep. Keep the rate sane on shared labs.' },
      ],
    },
    {
      id: 'db-shell',
      title: 'Database Shell',
      job: 'Log in to a database you found and read it, or pivot to code execution.',
      hue: 'database',
      sharedParams: [],
      defaultEngine: 'tb-mssqlclient',
      engines: [
        { builderId: 'tb-mssqlclient', tool: 'impacket-mssqlclient', label: 'MSSQL', teach: 'Microsoft SQL Server: Windows auth, pass-the-hash, and the xp_cmdshell path to code execution.', whenFact: 'service.mssql' },
        { builderId: 'tb-mysql', tool: 'mysql', label: 'MySQL / MariaDB', teach: 'Read databases and tables; watch for file-read and UDF paths.', whenFact: 'service.mysql' },
        { builderId: 'tb-psql', tool: 'psql', label: 'PostgreSQL', teach: 'Connect by URI; test the COPY-to-program code-execution path.', whenFact: 'service.postgresql' },
      ],
    },
  ];
})(typeof globalThis !== 'undefined' ? globalThis : this);
