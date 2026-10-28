# The Causal Frontier & Graph-Utility Ranking Engine

> [!IMPORTANT]
> **Core Thesis**: Penetration testing is a sequential decision problem under partial observability. At step 0, an automated advisor cannot telepathically know which single exploit will compromise an unfamiliar target; instead, it must rank plausible actions in order of their **epistemic and causal utility** toward the engagement objectives, updating that ranking in closed-loop response to positive findings, negative probes, and access transitions. OBOL achieves this without fragile per-move weight tuning by combining **Strict Proof Gating**, a **7-Tier Causal Frontier Hierarchy**, an **AND/OR Attack-Graph Distance & Keystone Lookahead Formula**, **A\* Dependable Route Planning**, and **Epoch-Scoped Dry-Probe Recovery**.

This document is the companion to [`INFERENCE.md`](INFERENCE.md) (which documents how raw terminal outputs are parsed into structured facts via the Wittgensteinian Contextual Inference Engine) and [`ARCHITECTURE.md`](ARCHITECTURE.md) (which documents the overall browser-local application architecture). Together, [`INFERENCE.md`](INFERENCE.md) and `RANKING.md` provide a complete mathematical and architectural specification of OBOL from raw terminal bytes to ranked operator guidance.

---

## 1. The Complete End-to-End Epistemic Pipeline

Every interaction in OBOL follows a deterministic seven-stage closed loop across [`assets/engine/parsers/`](assets/engine/parsers/index.js), [`assets/engine/facts.js`](assets/engine/facts.js), [`assets/engine/context.js`](assets/engine/context.js), [`assets/engine/phases.js`](assets/engine/phases.js), [`assets/engine/pack.js`](assets/engine/pack.js), [`assets/engine/command.js`](assets/engine/command.js), [`assets/engine/outcomes.js`](assets/engine/outcomes.js), and [`assets/ui/routes/path.js`](assets/ui/routes/path.js):

```mermaid
%%{init: {'flowchart': {'wrappingWidth': 460, 'nodeSpacing': 32, 'rankSpacing': 34}}}%%
flowchart TD
    Raw["<b>1. Raw Terminal Paste / Attached Log</b><br/>stdout, command, active target, copied-command queue"] --> Ingest["<b>2. Three-Tier Wittgensteinian Parser Cascade</b><br/>common.js -> Tier 1 Tool Parsers -> Tier 2 Shape -> Tier 3 Inference + Causal Entailment"]
    Ingest --> Ledger["<b>3. Scoped Fact Ledger & Identity Projection</b><br/>FactSet F, ProofState, context.resolve per host / credential / service, accessEpoch"]
    Ledger --> Outcome["<b>4. Attempt Outcome Classifier</b> (outcomes.js)<br/>success | completed-negative | authorization-denied | rejected | environment-error | partial"]
    Ledger --> Gates["<b>5. Proof Gating & Phase Frontier Filter</b> (pack.js + phases.js)<br/>eligible(a, F) && !settled(a, F) && !obsolete(a, F), prematurity(a, F) == 0"]
    Gates --> Ranker["<b>6. Causal Frontier & Graph-Utility Ranker</b> (nextActionsV2)<br/>Macro Tier in {-1..5} -> StageRank in {-1..4} -> S(a, F) = R * (Delta_d + 0.6*E + 0.25*K) + Modifiers"]
    Outcome --> DryLoop["<b>7. Intra-Card Command Selector & Dry-Probe Rotator</b> (command.js + path.js)<br/>Advances settled/tried commands; rotates dry-probed cards below untried hypotheses in accessEpoch"]
    Ranker --> DryLoop
    DryLoop --> UI["<b>Cockpit UI</b> (#/path, OBOL.coach)<br/>Expands Card #1 with Runnable Command #1"]
```

---

## 2. Formal State Representation: Facts, Scopes, and Access Epochs

### 2.1 The Fact Tuple and Proof States ([`assets/engine/facts.js`](assets/engine/facts.js))

The engagement state is a finite set of structured facts $\mathcal{F} = \lbrace f_1, f_2, \dots, f_n \rbrace$. Each fact $f \in \mathcal{F}$ is a tuple:

```math
f = (\text{kind},\, \text{scope},\, \text{value},\, \text{state},\, \text{source},\, t_{\text{created}})
```

where:
- $\text{kind} \in \mathcal{K}$ is a hierarchical dotted predicate (e.g., `port:445`, `smb.readable_share`, `ad.acl_lead`, `credential.available`, `access.admin`, `objective.root_flag`).
- $\text{scope}$ binds the observation to a network entity (`host:<ip>` or `domain:<fqdn>`).
- $\text{value}$ is a structured JSON payload carrying extracted parameters (e.g., `{ user, password, nthash, domain }`, `{ targets: ["Exchange Windows Permissions"] }`, `{ path: "C:\\Users\\Administrator\\Desktop\\root.txt" }`).
- $\text{state} \in \lbrace \texttt{supported}, \texttt{refuted}, \texttt{inconclusive} \rbrace$ is the epistemic proof state (`OBOL.facts.ProofState`).
- $t_{\text{created}} \in \mathbb{R}^+$ is the monotonic timestamp of ingestion.

For any scoped fact set $F \subseteq \mathcal{F}$, the set of **proven fact kinds** is defined solely over $\texttt{supported}$ facts:

```math
K(F) = \{\, f.\text{kind} \mid f \in F \;\land\; f.\text{state} = \texttt{supported} \,\}
```

A `refuted` or `inconclusive` fact never satisfies a positive prerequisite gate. Deduplication is enforced on the canonical fingerprint $(\text{kind}, \text{scope}, \text{claim}(f))$.

### 2.2 Identity-Scoped Context Projection ([`assets/engine/context.js`](assets/engine/context.js))

In a multi-host, multi-credential engagement, flat global booleans cause cross-account and cross-host contamination (for example, an administrative proof earned on Host A or by Account 1 falsely unlocking privileged commands on Host B or for Account 2).

Before evaluating eligibility or command filling, `OBOL.context.resolve` constructs an identity-coherent projection $F_{\text{ctx}} = \Pi(\mathcal{F}, \text{target}, \text{credId}, \text{service}, \text{locus})$:

1. **Host Isolation**: Only facts scoped to `host:<target>` (and `domain:<fqdn>` when `<target>` is proven to belong to `<fqdn>`) enter $F_{\text{ctx}}$.
2. **Credential Coherence**: Username, plaintext password, NTLM hash, and authentication realm (`domain` vs. local `.`) are drawn atomically from the single selected credential $c^* = \text{credId}$, never mixing one principal's username with another principal's secret.
3. **Service-Scoped Privilege Proof**: Remote administrative facts (`access.admin`) are filtered by the command's transport service (`smb`, `winrm`, `ldap`, `wmi`, `ssh`) and the selected `credentialId`, while on-host session privileges (`access.system`, `foothold.windows`, `foothold.linux`) are available only to commands whose execution locus is `onhost` (`OBOL.pack.commandExecutionLocus(cmd) === 'onhost'`).

### 2.3 The Access Epoch Signature ([`accessEpoch` in `assets/engine/pack.js`](assets/engine/pack.js))

An operator frequently runs a probe under anonymous access (finding nothing), later recovers a domain credential, and later still escalates to Domain Admin. A command or move that failed or returned empty in an earlier privilege state must be re-eligible once new access is achieved.

OBOL formalizes this via the **Access Epoch function** $\text{Epoch}(F)$, which maps the current fact set to a canonical privilege-and-material state string:

```math
\text{Epoch}(F) = \text{join}\Big(\big[\, \text{adm}(F),\; \text{fh}(F),\; \text{creds}(F),\; \text{hashes}(F) \,\big]\Big)
```

where:
- $\text{adm}(F) \in \lbrace \texttt{adm:root}, \texttt{adm:system}, \texttt{adm:admin}, \emptyset \rbrace$
- $\text{fh}(F) \in \lbrace \texttt{fh:win}, \texttt{fh:lin}, \texttt{fh:shell}, \emptyset \rbrace$
- $\text{creds}(F) = \texttt{cred:} + \text{sort}\big(\lbrace u : \text{secType} : \text{fingerprint}(v) \rbrace\big)$ over all held credentials
- $\text{hashes}(F) = \texttt{h:} + \text{sort}\big(\lbrace \texttt{asrep}, \texttt{tgs}, \texttt{ntlm} \rbrace \cap K(F)\big)$

If all four components are empty, $\text{Epoch}(F) = \texttt{anon}$. Whenever a new credential is recovered, a hash is captured, a foothold is landed, or administrative access is proven, $\text{Epoch}(F)$ transitions to a new string, automatically resetting epoch-scoped command-retry and dry-probe counters (`commandTriedInEpoch` and `moveDryTriesInEpoch`).

---

## 3. The Attack Graph: Proof Gating, Settlement, and Phase Prematurity

### 3.1 Move Declarations and Eligibility Gates ([`assets/engine/pack.js`](assets/engine/pack.js))

The move library $\mathcal{A}$ (`data/packs-bundle.js`, 355 moves across 19 packs) is a directed hypergraph where facts are vertices and moves are hyperedges. Each move $a \in \mathcal{A}$ declares:

- $\text{req}_{\text{all}}(a) \subseteq \mathcal{K}$: mandatory conjunctive prerequisite fact kinds.
- $\text{req}_{\text{any}}(a) \subseteq \mathcal{K}$: disjunctive trigger fact kinds (at least one must hold if non-empty).
- $\text{prod}(a) \subseteq \mathcal{K}$: outcome fact kinds minted when $a$ succeeds.
- $\text{os}(a) \subseteq \lbrace \texttt{linux}, \texttt{windows}, \texttt{macos} \rbrace$: operating system compatibility.
- $\text{locus}(a) \in \lbrace \texttt{R}, \texttt{F}, \texttt{I} \rbrace$: execution locus (`R` = Remote from attacker host, `F` = Foothold one-shot on target, `I` = Interactive on target).
- $\text{priority}(a) \in [0, 100]$: authored tie-breaking priority.
- $\text{transition}(a)$: semantic DAG transition role (e.g., `asrep_roast`, `crack_asrep`, `kerberoast`, `crack_tgs`, `map_acl`, `map_graph`, `map_manual`, `gpp`, `loot_browse`, `dcsync`, `privesc_orient`, `privesc_act`, `user_flag_win`, `root_flag_win`, `foothold_win`).

A move $a$ is **eligible** under fact set $F$ (`a.eligible(F)`) if and only if:

```math
\text{eligible}(a, F) \iff \text{osCompatible}(a, F) \;\land\; \Big(\forall k \in \text{req}_{\text{all}}(a),\, k \in K(F)\Big) \;\land\; \Big(\text{req}_{\text{any}}(a) = \emptyset \;\lor\; \exists k \in \text{req}_{\text{any}}(a),\, k \in K(F)\Big)
```

### 3.2 Settlement and Obsolescence (`a.settled(F)` and `a.obsolete(F)`)

A move $a$ is **settled** when its epistemic purpose has already been fulfilled on the active target:

```math
\text{settled}(a, F) \iff \text{prod}(a) \neq \emptyset \;\land\; \Big(\forall k \in \text{prod}(a),\, k \in K(F)\Big) \;\land\; \neg\text{PartialUnfinished}(a, F)
```

where $\text{PartialUnfinished}(a, F)$ holds if the most recent execution of $a$ was classified as `partial` (e.g., a truncated scan output) without a subsequent conclusive completion receipt, or if $a$ is a multi-service validator (`validate-credential`) with remaining untested services.

A move $a$ is **obsolete** (`a.obsolete(F)`) if a later achievement makes it redundant:
1. Any kind in `a.obsolete_when` is present in $K(F)$.
2. $a$ is a low-privilege foothold acquisition move (whose $\text{prod}(a)$ consists only of `access.shell`, `foothold.*`, or `web.*` kinds) and administrative or root access (`access.root`, `access.admin`, or `access.system`) is already held in $K(F)$.

Thus, the **live candidate set** $\mathcal{L}(F) \subseteq \mathcal{A}$ passed to the ranker is:

```math
\mathcal{L}(F) = \{\, a \in \mathcal{A} \mid \text{eligible}(a, F) \;\land\; \neg\text{settled}(a, F) \;\land\; \neg\text{obsolete}(a, F) \;\land\; a.\text{id} \notin \text{Done}(F) \,\}
```

### 3.3 The Six-Phase Frontier Model ([`assets/engine/phases.js`](assets/engine/phases.js))

Independent of the fine-grained ranker, OBOL projects the engagement onto an ordered six-phase sequence:

```math
\Phi = \langle \texttt{recon}_0,\, \texttt{enum}_1,\, \texttt{creds}_2,\, \texttt{access}_3,\, \texttt{escalate}_4,\, \texttt{loot}_5 \rangle
```

Each fact kind $k \in \mathcal{K}$ maps to a phase index $\phi(k) \in \lbrace 0, \dots, 5 \rbrace$ via longest-prefix matching (`PHASE_RULES`). The target's current reached phase and active frontier index are:

```math
\text{Reached}(F) = \max_{k \in K(F)} \phi(k), \qquad \text{Frontier}(F) = \min\big(5,\, \text{Reached}(F) + 1\big)
```

The **prematurity** of a move $a$ with phase $\phi(a)$ is:

```math
\text{prematurity}(a, F) = \max\big(0,\, \phi(a) - \text{Frontier}(F)\big)
```

In the Cockpit UI ([`assets/ui/routes/path.js`](assets/ui/routes/path.js), `OBOL.coach` in code), moves in $\mathcal{L}(F)$ with $\text{prematurity}(a, F) = 0$ and at least one runnable, untried command populate **Ready Now (`onFlow`)**; moves with $\text{prematurity}(a, F) > 0$ populate **Coming Up (`comingUp`)**; and informational writeup checks (`isReportOnly(a, A)`) populate **Report Checks (`reportChecks`)**.

---

## 4. Why Pure Priority Weights Fail: The Theory of Causal Frontier Tiers

### 4.1 The Fragility of Flat Weight Ladders

In a traditional weighted-sum recommender, every rule adds a numeric bonus $+w_i$ to a single scalar score:

```math
S_{\text{legacy}}(a, F) = S_{\text{graph}}(a, F) + \sum_{i} w_i \cdot \mathbb{I}[\text{rule}_i(a, F)]
```

In a stateful penetration testing engine, this architecture suffers from three structural failure modes:

1. **The Recency Window Decay Trap**: If "newly unlocked" moves are detected solely by a wall-clock timestamp window (for example, facts created within $\Delta t \le 2\text{ s}$ of $\max t$), then as soon as an operator runs a single post-authentication command (such as reading `user.txt` 10 seconds after validating a credential), the credential fact ages out of the 2-second window. All remaining credential-unlocked moves drop back to the baseline tier unless ad-hoc rules forcibly pin them upward.
2. **Macro-Stage Collision in a Flat Tier**: Once multiple engagement stages (pre-auth discovery, authenticated enumeration, active hash cracking, ACL exploitation, and endgame flag capture) are all pinned into the same tier (`tier = 2`), the only way to prevent an earlier stage's move from outranking a later stage's move is to invent an escalating ladder of magic weights $(+3.0, +4.5, +5.8, +6.0, +7.0, +24.0)$.
3. **Cross-Term Interference**: Because those stage bonuses are added directly into the continuous graph utility score $S_{\text{graph}}(a, F)$, any change to the move pack that alters a move's fan-out (`keystone`) or graph distance (`progA`) can shift $S_{\text{graph}}$ by $0.5\text{ - }2.0$ points, causing one rule's $+4.5$ move to unexpectedly leapfrog another rule's $+5.8$ move.

### 4.2 Structural Separation: Macro-Stage Tier vs. Micro-Stage Role vs. Graph Utility

OBOL resolves all three failure modes by decomposing ranking into three strictly orthogonal, lexicographically ordered dimensions in [`nextActionsV2`](assets/engine/pack.js):

```math
\mathbf{RankKey}(a, F) = \big(\text{Tier}(a, F),\; \text{StageRank}(a, F),\; S(a, F),\; \text{priority}(a),\; -\text{toolkitRank}(a),\; -\text{locusRank}(a)\big)
```

1. **Macro-Stage Causal Frontier Tier**, $\text{Tier}(a, F) \in \lbrace -1, 0, 1, 2, 3, 4, 5 \rbrace$: Encodes **which causal frontier of the kill-chain** the move belongs to given the current persistent state $K(F)$. Because Tier 5 $>$ Tier 4 $>$ Tier 3 $>$ Tier 2 $>$ Tier 1 $>$ Tier 0 $>$ Tier $-1$ is a strict lexicographic partition, an Earned Material transform in Tier 4 (such as cracking a captured TGS hash or abusing a discovered writable ACL) **automatically** ranks above every general authenticated probe in Tier 3, with zero magic weights added to $S(a, F)$.
2. **Within-Tier Structural Role**, $\text{StageRank}(a, F) \in \lbrace -1, 0, 1, 2, 3, 4 \rbrace$: Orders the operational sub-roles within the same macro-tier by action cost and directness (e.g., within Tier 3: capturing an unmet 1-command local flag objective $>$ running a 1-command fast escalation probe $>$ running a multi-step whole-domain graph collector $>$ manual enumeration).
3. **Pure Graph Utility Score**, $S(a, F) \in \mathbb{R}$: Breaks ties between moves sharing the exact same $(\text{Tier}, \text{StageRank})$ using the topology of the attack graph (goal-distance reduction $\Delta d$, 1-step enablement $E$, and keystone breadth $K$, scaled by epistemic reliability $R$).

### 4.3 Complete Specification of the 7 Causal Frontier Tiers

Each live move $a \in \mathcal{L}(F)$ is initialized to its base epistemic tier:

```math
\text{Tier}_{\text{base}}(a, F) = \begin{cases}
-1 & \text{if } \text{Speculative}(a, F) \land \neg\text{Earned}(a, F) \\
2 & \text{if } \text{Fresh}(a, F) \\
1 & \text{if } \text{Earned}(a, F) \\
0 & \text{otherwise}
\end{cases}
```

where $\text{Fresh}(a, F) \iff \text{eligible}(a, K(F)) \land \neg\text{eligible}(a, K_{\text{before}}(F))$ (subject to anti-thrash guards that suppress low-level recon pings when a high-value lead is already held, and defer generic host LPE fallbacks `a.dcDefer` on unmapped Domain Controllers).

The promotion operator $\text{promote}(t, r)$ then elevates $(\text{Tier}, \text{StageRank}) \leftarrow \max\big((\text{Tier}, \text{StageRank}), (t, r)\big)$ across the active persistent state:

| Causal Frontier Tier | Sub-Role (`stageRank`) | Persistent State Condition & Transition Role | Operational Meaning |
| :--- | :---: | :--- | :--- |
| **Tier 5: Endgame Cash-In Frontier** | `5.3` | Admin/System/Root held (or `credentialProbeAllowed`) $\land$ uncaptured `objective.root_flag` | Immediate root/administrator flag proof capture (`root_flag_win` / `flag-hunt-root-*`). |
| | `5.2` | `adPosture == dcsync_ready` (with `ad.control_paths` $\in K(F)$ held) before `loot.ntds` / `access.admin`, OR Admin held with uncaptured `objective.local_flag` | Domain takeover cash-in (`dcsync`) or remaining local flag proof capture after admin compromise. |
| | `5.1` | Admin/System/admin-cred held on Windows surface $\land$ `access.shell` $\notin K(F)$ $\land$ `transition == foothold_win` | Establishing an interactive administrative shell (`win-interactive-shell`) once flags are handled. |
| **Tier 4: Earned Material / Active Lead in Hand** | `4.4` | `hash.tgs` $\in K(F)$ (`crack_tgs`), `hash.asrep` $\in K(F)$ (`crack_asrep`), or `gpp_cpassword` candidate in hand (`gpp`) | Deterministic offline secret recovery from a captured cryptographic artifact. |
| | `4.3` | Confirmed `ad.acl_lead` / `ad.group_joined` / `ad.attack_paths` (`map_acl`), confirmed host privesc vector (`privesc_act`), `ad.user_list` pre-cred (`asrep_roast`), or `loot.files` / `config.review` (`gpp`) | Immediate exploitation of a proven vulnerability, writable ACL, user list, or downloaded policy file. |
| | `4.2` | Secondary ACL abuse (`ad-acl-abuse`) or readable SMB share pre-cred (`gpp`, `loot_browse`) | Share spidering, file extraction, and on-host ACL abuse twin. |
| **Tier 3: Authenticated / Foothold Frontier** | `3.4` | `validateFirst` (`credential.validated` producer), OR credential/foothold held on active Windows surface with uncaptured `objective.local_flag` (`user_flag_win`) | Validating a newly recovered credential first, then capturing the reachable user flag (`user.txt`). |
| | `3.3` | Authenticated AD unmapped fast probes (`map_acl`, `kerberoast`), or unindicated host foothold orientation (`privesc_orient`, `linux-enum`, `windows-enum`) | Single-command escalation probes (`bloodyad-acl`, `kerberoast`) and initial local privesc sweeps. |
| | `3.2` | Authenticated AD unmapped graph collection (`map_graph`) | Automated whole-domain graph collection (`bloodhound-collect`). |
| | `3.1` | Authenticated AD manual path-finding (`map_manual`), interactive user shell (`foothold_win`), or fallback local flag | Multi-step manual LDAP/DACL enumeration (`ad-path-manual`) and interactive foothold login. |
| **Tier 2: Pre-Auth Surface & Fresh Recon** | `2.2` | Post-version-scan anonymous AD openers (`recon-smb-anon`, `ad-anon-ldap-enum`, `ad-user-enum`) or non-AD web content discovery (`recon-web-triage`, `content-discovery`, etc.) | Primary unauthenticated attack-surface enumeration after port/service discovery. |
| | `2.0` | All other freshly unlocked moves $(\text{Fresh}(a, F) = \text{true})$ | Newly unlocked service probes from the latest evidence batch. |
| **Tier 1: Indicated Frontier** | `1.0` | $\text{Earned}(a, F) = \text{true}$ from an earlier batch | Evidenced moves unlocked in prior turns that remain available. |
| **Tier 0: Baseline Frontier** | `0.0` / `-1` | Standard eligible moves (with passive L2 poisoners / optional NSE scans at `stageRank = -1`) | General methodology moves and passive listeners (`responder`, `mitm6`). |
| **Tier -1: Speculative Frontier** | `-1` | $\text{Speculative}(a, F) \land \neg\text{Earned}(a, F)$, or cross-OS / non-AD mismatch | Blind CVE exploits, unindicated password sprays, and out-of-context moves. |

---

## 5. Mathematical Formulation of Graph Distance, Reliability, and Utility Score

Within any `(Tier, StageRank)` bucket, OBOL ranks moves by their **Expected Graph Utility Score** $S(a, F)$. Every term in $S(a, F)$ is computed directly from the wiring of the move graph $\mathcal{A}$ and the current fact set $F$.

### 5.1 Recursive AND/OR Attack-Graph Distance (`v2GoalDistance`)

Let $G$ be the engagement goal set. With flags enabled (`V2_GOALS`):

```math
G = \{\texttt{objective.root\_flag},\; \texttt{objective.local\_flag},\; \texttt{objective.flag},\; \texttt{access.root},\; \texttt{access.admin},\; \texttt{access.system},\; \texttt{loot.ntds},\; \texttt{ad.domain\_admin}\}
```

With flags disabled (`V2_GOALS_NO_FLAGS`):

```math
G_{\text{no-flags}} = \{\texttt{access.root},\; \texttt{access.admin},\; \texttt{access.system},\; \texttt{loot.ntds},\; \texttt{ad.domain\_admin}\}
```

To prevent an already-achieved intermediate goal (such as `objective.local_flag` after capturing `user.txt`) from zeroing the distance to the remaining goals, `nextActionsV2` defines the **active unachieved goal set**:

```math
G_{\text{active}}(F) = \begin{cases}
\{\, g \in G \mid g \notin K(F) \,\} & \text{if } \{\, g \in G \mid g \notin K(F) \,\} \neq \emptyset \\
G & \text{otherwise}
\end{cases}
```

For any set of held fact kinds $H \subseteq \mathcal{K}$, let $\mathcal{P}(k) = \lbrace m \in \mathcal{A} \mid k \in \text{prod}(m) \rbrace$ be the set of moves that produce fact kind $k$. The minimal step distance $d(H, G_{\text{active}})$ through the AND/OR prerequisite hypergraph is defined mutually recursively over fact nodes $\text{fc}(k)$ (OR-nodes) and move nodes $\text{mc}(m)$ (AND-nodes):

```math
\text{fc}(k, H) = \begin{cases}
0 & \text{if } k \in H \\
\min_{m \in \mathcal{P}(k)} \text{mc}(m, H) & \text{if } \mathcal{P}(k) \neq \emptyset \\
\infty & \text{otherwise}
\end{cases}
```

```math
\text{mc}(m, H) = 1 + \sum_{r \in \text{req}_{\text{all}}(m)} \text{fc}(r, H) + \begin{cases}
\min_{r \in \text{req}_{\text{any}}(m)} \text{fc}(r, H) & \text{if } \text{req}_{\text{any}}(m) \neq \emptyset \\
0 & \text{if } \text{req}_{\text{any}}(m) = \emptyset
\end{cases}
```

with cycle detection (returning $\text{fc}(k, H) = \infty$ if $k$ is already on the active recursion stack) and memoization ceiling `V2_INF = 99`. The distance from state $H$ to the active goal set is:

```math
d(H, G_{\text{active}}) = \min_{g \in G_{\text{active}}} \text{fc}(g, H)
```

### 5.2 Direct Goal Progress $\Delta d(a, F)$ (`v2ProgressFrom`)

Let $H_0 = K(F)$ be the currently proven fact kinds, $d_0 = d(H_0, G_{\text{active}})$, and $H_a = H_0 \cup \text{prod}(a)$ be the hypothetical fact set after move $a$ succeeds, with $d_a = d(H_a, G_{\text{active}})$. The **Direct Goal Progress** $\Delta d(a, F)$ (`progA`) is:

```math
\Delta d(a, F) = \begin{cases}
0 & \text{if } d_0 \ge \infty \;\land\; d_a \ge \infty \\
5 & \text{if } d_0 \ge \infty \;\land\; d_a < \infty \\
\max(0,\, d_0 - d_a) & \text{otherwise}
\end{cases}
```

### 5.3 Epistemic Prior Reliability $R(a, F)$ (`v2Reliability`)

Not all moves in an attack graph are equally likely to succeed. A move that exploits a **confirmed** vulnerability or cracks an **already captured** hash is near-deterministic, whereas firing a kernel exploit or password spray without a prior indicator is a low-probability gamble.

OBOL defines three epistemic predicates over a move $a$ and held kinds $H$:

1. **Evidence Fact (`v2EvidenceFact(k)`)**: A fact kind $k$ is hard evidence if it matches:
   - `V2_EVIDENCE_RE`: `/^(credential\.|hash\.|kerberos\.tickets|foothold\.|access\.|privesc\.|ad\.|smb\.(shares|null_session|guest_session|writable_share|ms17_010)|web\.|http\.(methods|exposed)|db\.|mssql\.|service\.version|vuln\.|exploit\.|loot\.|file\.|snmp\.|nfs\.|ftp\.|redis\.|rsync\.|tftp\.|dns\.zone|sccm\.|adcs\.)/`
   - excluding pure reachability/discovery facts (`*.reachable`, `ad.dc_candidate`, `ad.domain_known`, `ad.base_dn`).
   - **Specific Vulnerability / Artifact Fact (`V2_SPECIFIC_RE`)**: `/^(vuln\.|exploit\.|privesc\.|adcs\.vulnerable|smb\.(ms17_010|writable_share)|http\.(methods|exposed)|web\..*confirmed|file\.|db\.admin|mssql\.linked|ad\.(acl_lead|control_paths|gpo_writable|zerologon|nopac|maq_allow|coerced_auth|unconstrained|delegation|sid_history|computer_added)|sccm\.)/` (excluding generic `privesc.leads` and `vuln.candidates`).
2. **Earned Move (`v2Earned(a, H)`)**: Move $a$ is *earned* if:
   - it is not tagged `a.speculative`, OR one of its gate facts in $H$ is a specific indicator (`V2_SPECIFIC_RE`); **AND**
   - if $a$ claims a privilege goal (`V2_PRIV`: `access.root`, `access.admin`, `access.system`, `loot.ntds`, `ad.domain_admin`) or is an AD-lead consumer, it is backed by a satisfied specific indicator (`V2_SPECIFIC_RE`) or hard credential/access (`credential.available`, `hash.ntlm`, `hash.krbtgt`, `kerberos.tickets`, `access.admin`, `access.system`, `access.root`) in $H$; otherwise it is backed by any satisfied `v2EvidenceFact` gate in $H$.
3. **Speculative Move (`v2Speculative(a, H)`)**: Move $a$ is *speculative* if:
   - $a.\text{speculative} = \text{true}$ and none of its gate facts in $H$ satisfies `V2_SPECIFIC_RE`; **OR**
   - $a$ is not indicated (`!v2Indicated(a, H)`) yet claims a foothold (`foothold.*`, `access.shell`, `web.rce`) or a validated credential (`credential.available`, `credential.plaintext`).

From these predicates, the **Epistemic Prior Reliability** $R(a, H) \in \lbrace 1.00, 0.80, 0.30, 0.25 \rbrace$ is:

```math
R(a, H) = \begin{cases}
1.00 & \text{if } \text{Earned}(a, H) \quad \text{(proven indicator or captured material in hand)} \\
0.25 & \text{if } \text{Speculative}(a, H) \quad \text{(unindicated exploit / blind spray gamble)} \\
0.30 & \text{if } \neg\text{Earned}(a, H) \;\land\; \text{prod}(a) \cap \texttt{V2\_PRIV} \neq \emptyset \quad \text{(unindicated privilege shortcut)} \\
0.80 & \text{otherwise} \quad \text{(standard deterministic enumeration / discovery)}
\end{cases}
```

### 5.4 One-Step Deepest Enablement $E(a, F)$ and Bounded Keystone Breadth $K(a, F)$

A pivotal intermediate move (such as dumping a user list, collecting a TGS hash, or validating a credential) may not reach a terminal flag in 1 step $(\Delta d(a, F) = 0)$, but it **unlocks** downstream moves that do.

Let $U(a, F)$ be the set of moves in $\mathcal{A}$ that are currently **ineligible** under $H_0 = K(F)$ but become **eligible** under $H_a = H_0 \cup \text{prod}(a)$:

```math
U(a, F) = \{\, b \in \mathcal{A} \setminus \{a\} \mid \neg\text{eligible}(b, H_0) \;\land\; \text{eligible}(b, H_a) \,\}
```

For each newly unblocked move $b \in U(a, F)$, let $R_b = R(b, H_a)$ be its reliability in the post-move state $H_a$, and let $\Delta d_b(a, F)$ be its goal progress from $H_a$:

```math
\Delta d_b(a, F) = \begin{cases}
1 & \text{if } \text{InEscalationWindow}(H_0) \;\land\; \texttt{hash.tgs} \in \text{prod}(a) \setminus H_0 \;\land\; \texttt{credential.available} \in \text{prod}(b) \\
\text{v2ProgressFrom}(d_a,\, H_a,\, \text{prod}(b),\, \mathcal{P},\, G_{\text{active}}) & \text{otherwise}
\end{cases}
```

where $\text{InEscalationWindow}(H_0) \iff \texttt{credential.available} \in H_0 \land H_0 \cap \lbrace \texttt{access.admin}, \texttt{access.system}, \texttt{loot.ntds} \rbrace = \emptyset$. This escalation-aware lookahead recognizes that when a low-privilege credential is already held in $H_0$, roasting a service ticket (`hash.tgs` $\to$ `crack-tgs`) yields a **new escalated credential** even though the boolean kind `credential.available` is already present in $H_0$.

From $U(a, F)$, OBOL computes two 1-step lookahead quantities:

**1. Deepest 1-Step Enablement $E(a, F)$ (`enable`)** - the single highest reliability-weighted progress among all doors that $a$ opens:

```math
E(a, F) = \max_{b \in U(a, F)} \big(R_b \cdot \Delta d_b(a, F)\big) \qquad (\text{with } E(a, F) = 0 \text{ if } U(a, F) = \emptyset)
```

**2. Bounded Keystone Breadth $K(a, F)$ (`keystone`)** - the reliability-tempered breadth of the attack surface unblocked by $a$, giving every newly unblocked move $b \in U(a, F)$ a base weight of $0.5$ plus its goal progress $\Delta d_b(a, F)$, capped at $K_{\max} = 2.5$ (`V2_KEYSTONE_CAP`):

```math
K_{\text{raw}}(a, F) = \min\left(2.5,\; \sum_{b \in U(a, F)} R_b \cdot \big(0.5 + \Delta d_b(a, F)\big)\right)
```

Because keystone fan-out is a **middle-game** pivot metric (meant to help reach a winning position, never to displace an endgame cash-in or promote post-compromise persistence), $K(a, F)$ is zeroed for direct privilege cash-ins and deprioritized side-quests:

```math
K(a, F) = \begin{cases}
0 & \text{if } \big(\text{prod}(a) \cap \texttt{V2\_PRIV} \neq \emptyset\big) \;\lor\; \big(\texttt{deprioritize\_when}(a) \cap H_0 \neq \emptyset\big) \\
K_{\text{raw}}(a, F) & \text{otherwise}
\end{cases}
```

### 5.5 The Complete Graph Utility Score Formula $S(a, F)$

Combining Direct Progress $\Delta d(a, F)$, Deepest Enablement $E(a, F)$, Keystone Breadth $K(a, F)$ (with weight $w_K = 0.25$), Epistemic Prior Reliability $R(a, F)$, and bounded situational modifiers yields the complete scoring equation in [`nextActionsV2`](assets/engine/pack.js):

```math
S(a, F) = R(a, F) \cdot \Big(\Delta d(a, F) + 0.6 \cdot E(a, F) + 0.25 \cdot K(a, F)\Big) + \Omega_{\text{obj}}(a, F) + \Phi_{\text{focus}}(a) + \Phi_{\text{risk}}(a, F) - \Psi_{\text{side}}(a, F)
```

where every modifier is explicitly bounded and defined. First, **Endgame Uncaptured Objective Pull**, $\Omega_{\text{obj}}(a, F)$:

```math
\Omega_{\text{obj}}(a, F) = \begin{cases}
2.0 \quad (\texttt{V2\_OBJECTIVE\_W}) & \text{if flags enabled } \land \exists p \in \text{prod}(a) \cap \{\texttt{objective.root\_flag},\; \texttt{objective.local\_flag},\; \texttt{objective.flag}\} \text{ with } p \notin H_0 \\
0 & \text{otherwise}
\end{cases}
```

The remaining three modifiers are:

- **Profile Focus Alignment**, $\Phi_{\text{focus}}(a)$: $+0.5$ if any fact in $\text{prod}(a)$ matches the active machine profile's `focusPrefixes` (e.g., `ad.` on an AD profile), else $0$.
- **Blind Spray Risk Penalty**, $\Phi_{\text{risk}}(a, F)$: $-0.5$ if $\text{transition}(a) = \texttt{spray}$ and neither `policy.lockout` nor `smb.null_session` is proven in $H_0$ (penalizing account-lockout risk), else $0$.
- **Deprioritized Side-Quest Suppression**, $\Psi_{\text{side}}(a, F)$: $+5.0$ if `a.deprioritize_when` intersects $H_0$ (e.g., ticket-forging persistence once `loot.ntds` is already held), else $0$. (Cross-context mismatches - AD moves on non-AD boxes or Windows shell moves without a Windows surface - are sent to $\text{Tier} = -1$, $\text{StageRank} = -1$ with penalty $-20$ / $-10$).

#### Worked Numerical Example: Authenticated AD Frontier (`Tier = 3, StageRank = 3`)

Suppose the operator has validated a low-privilege domain user (`credential.available`, `credential.validated`) on an unmapped AD Domain Controller (`port:88`, `port:389`, `port:445`, `ad.domain_known`) and captured `user.txt` (`objective.local_flag`). Three moves compete in `Tier = 3, StageRank = 3` (with `laps-read` in `Tier = 0`):

1. **`bloodyad-acl` (`map_acl`, priority 92)**:
   - Unblocks 6 moves (`dcsync`, `shadow-credentials`, `delegation-abuse`, `ad-acl-abuse`, `dnsadmins-abuse`, `crack-identify`).
   - Because `dcsync` is earned under $H_a$ $(R_b = 1.0)$ and reaches `loot.ntds` in 1 step $(\Delta d_b = 1)$, $E = 1.0 \times 1 = 1.0$, and $K = \min(2.5, \sum R_b(0.5 + \Delta d_b)) = 2.5$.
   - $S(\texttt{bloodyad-acl}, F) = 0.80 \times (0 + 0.6(1.0) + 0.25(2.5)) = \mathbf{0.980}$.
2. **`kerberoast` (`kerberoast`, priority 89)**:
   - Unblocks 3 moves (`crack-tgs` with $R_b = 1.0$ and $\Delta d_b = 1$ via escalation-aware lookahead; `crack-identify` and `crack-kerberoast` with $R_b = 0.8$ and $\Delta d_b = 0$).
   - $E = 1.0 \times 1 = 1.0$, and $K = 1.0(0.5 + 1.0) + 0.8(0.5) + 0.8(0.5) = 2.3$.
   - $S(\texttt{kerberoast}, F) = 0.80 \times (0 + 0.6(1.0) + 0.25(2.3)) = \mathbf{0.940}$.
3. **`laps-read` (narrow attribute read, priority 92)**:
   - Unblocks 1 move (`crack-identify` with $R_b = 0.8$ and $\Delta d_b = 0$).
   - $E = 0$, $K = 0.8(0.5) = 0.4$.
   - $S(\texttt{laps-read}, F) = 0.80 \times (0 + 0 + 0.25(0.4)) = \mathbf{0.080}$.

Purely from graph wiring (6 unblocked doors $>$ 3 unblocked doors $>$ 1 unblocked door), $S(\texttt{bloodyad-acl}) = 0.980 > S(\texttt{kerberoast}) = 0.940 > S(\texttt{laps-read}) = 0.080$, with zero per-move magic weights.

---

## 6. The 11-Level Lexicographic Sort & Tie-Breaking Hierarchy

Given the scored candidate list, `nextActionsV2` ([`assets/engine/pack.js`](assets/engine/pack.js)) sorts moves $x, y \in \mathcal{L}(F)$ using a strict 11-level lexicographic comparator:

1. **Selected-Identity Validation Guard (`selectedIdentityPending`)**: When the operator has explicitly selected an unvalidated credential in the UI context bar, moves that can validate that identity (`credential.validated` in $\text{prod}(a)$ or `credentialProbeAllowed(a, F)`) sort first.
2. **Causal Frontier Tier (`y.tier - x.tier`)**: Higher macro-stage frontier tier $(\text{Tier} \in \lbrace 5, 4, 3, 2, 1, 0, -1 \rbrace)$ wins.
3. **Opening Diagnostic & Elimination Breadth (`earlyRecon` within `Tier == 2`)**: Before `scan.nmap.version`, a foothold, or a credential is held:
   - The thorough service scan (`scan.nmap.version` in $\text{prod}(a)$, rank 0) leads curated diagnostic openers (with $a.\text{diagnostic} = \text{true}$, rank 1), which lead all other fresh moves (rank 2).
   - Between two diagnostic openers $(dx = dy = 1)$, the move with greater **Elimination Breadth** (measured by $|\text{eliminates}(a)|$, the count of attack lanes it rules in or out) wins.
4. **Validate-Before-Use Guard (`validateFirst`)**: While holding an unvalidated credential with no authenticated session yet, moves that validate the credential sort ahead of moves that spend it.
5. **Map-Before-Specialize Guard (`specializeHold`)**: While holding a credential on an unmapped domain with no foothold, general domain mapping and roasting sort ahead of specialized misconfiguration exploits (`adcs.vulnerable`, `credential.certificate`, `ad.trusts`, `sccm.*`).
6. **Within-Tier Structural Role (`y.stageRank - x.stageRank`)**: Higher structural sub-role within the current Causal Frontier Tier $(\text{StageRank} \in \lbrace 4, 3, 2, 1, 0, -1 \rbrace)$ wins.
7. **Continuous Graph Utility Score (`y.score - x.score`)**: Higher $S(a, F)$ wins.
8. **Authored Move Priority (`y.a.priority - x.a.priority`)**: Higher pack-authored tie-break priority wins.
9. **House Toolkit Preference (`moveToolkitRank(x.a) - moveToolkitRank(y.a)`)**: Among genuine twins equal on tier, stage role, graph score, and priority, moves backed by `PREFERRED_TOOLKIT` (`nxc`, `impacket-*`, `bloodyad`, `bloodhound-python`, `certipy`, `ffuf`, `hashcat`, `ligolo-ng`, `evil-winrm`) win (rank 0 vs. rank 1).
10. **Remote-First Execution Locus (`locusRank(x.a.locus) - locusRank(y.a.locus)`)**: Lower-friction execution locus wins: Remote (`R = 0`) $<$ Foothold one-shot (`F = 1`) $<$ Interactive (`I = 2`).
11. **Deterministic ID Tie-Break (`x.a.id < y.a.id`)**: Alphabetical `action.id` guarantees total determinism across JavaScript engines.

**Post-Sort AD Orientation Invariant**: On an AD target where neither `ad.dc_candidate` + `ad.domain_known` nor a foothold/credential has been established, if no AD orientation move (whose $\text{prod}(a)$ contains `ad.dc_candidate`, `ad.domain_known`, `ad.base_dn`, or `ad.anonymous_bind`) appears in indices `0..2`, the top-ranked orientation move is promoted to index 2 (slot `#3`) so the operator can always confirm domain parameters before service exploitation.

---

## 7. Full-Route A\* Attack Planner (`planPath` & `v2ActionCost`)

While `nextActionsV2` ranks the immediate next moves at the current frontier, `planPath(facts, pack, opts)` ([`assets/engine/pack.js`](assets/engine/pack.js)) computes the **complete minimum-cost sequence of moves** $\pi^* = \langle a_1, a_2, \dots, a_k \rangle$ from the current fact state $H_0 = K(F)$ to any goal in $G$.

### 7.1 Step Cost Function $c(a, H)$ (`v2ActionCost`)

At state $H \subseteq \mathcal{K}$, taking applicable move $a$ incurs step cost:

```math
c(a, H) = c_{\text{base}}(a, H) + 0.3 \cdot \text{locusRank}(a.\text{locus})
```

where:

```math
c_{\text{base}}(a, H) = \begin{cases}
12.0 & \text{if } \text{Speculative}(a, H) \;\land\; \neg\text{Earned}(a, H) \\
1.0 & \text{if } \text{Earned}(a, H) \\
8.0 & \text{if } \neg\text{Earned}(a, H) \;\land\; \text{prod}(a) \cap \texttt{V2\_PRIV} \neq \emptyset \\
1.5 & \text{otherwise (standard enumeration / discovery step)}
\end{cases}
```

and $\text{locusRank}(\texttt{R}) = 0$, $\text{locusRank}(\texttt{F}) = 1$, $\text{locusRank}(\texttt{I}) = 2$.

### 7.2 Admissibility and Optimality of the A\* Search

The A\* search maintains an open priority queue ordered by $f(H) = g(H) + h(H)$, where:
- $g(H)$ is the exact accumulated path cost $\sum_{i=1}^{m} c(a_i, H_{i-1})$ from $H_0$ to $H$.
- $h(H) = d(H, G)$ (`v2GoalDistance`) is the minimum number of moves required to reach any goal from $H$.

Because every move in the graph has step cost $c(a, H) \ge 1.0$, and any path of $k$ moves can reduce the step distance $d(H, G)$ by at most $k$ steps along the chosen AND-branch, $h(H) = d(H, G)$ is an **admissible heuristic** $(h(H) \le h^*(H))$. Furthermore, `planPath` enforces dynamic OS-family consistency (`osOkIn(a, st)`): once a path accrues a Linux foothold (`foothold.linux`), Windows-only moves are pruned from that branch (and vice versa), preventing impossible cross-OS plans.

---

## 8. Intra-Card Command Selection & Closed-Loop Dry-Probe Recovery

Ranking the right move card at `#1` is only half of the problem; an operator (especially a learner) expects **Command `#1` on Card `#1`** to be immediately runnable and to advance automatically when a command finishes or comes up empty.

### 8.1 Intra-Card Command Selection (`preferredCommandIndex` & `bestCommandIndex`)

Each move $a \in \mathcal{A}$ contains an ordered array of command variants $C(a) = \langle c_0, c_1, \dots, c_{m-1} \rangle$. When rendering a card or selecting its active command for execution locus $L \in \lbrace \texttt{remote}, \texttt{onhost} \rbrace$, `OBOL.command.bestCommandIndex` ([`assets/engine/command.js`](assets/engine/command.js)) and `OBOL.pack.preferredCommandIndex` ([`assets/engine/pack.js`](assets/engine/pack.js)) filter out any command $c_i$ that is:

1. **Settled (`commandSettled(c_i, F)`)**: Any fact in `c_i.settled_by` is already proven in $K(F)$ (for example, `bloodyAD ... get writable` settles as soon as `ad.acl_lead` is minted, promoting `add groupMember` to Command `#1`).
2. **Command-Gate or Port-Gate Ineligible (`commandIsEligible(c_i, F, a)`)**:
   - $c_i$ declares `requires_all` or `requires_any` facts not yet in $K(F)$ (e.g., `bloodyad-acl` mutation commands `#1` to `#10` require `requires_any: ["ad.acl_lead", "ad.group_joined", "ad.attack_paths", "ad.control_paths"]`).
   - The tool for $c_i$ requires a specific TCP transport port (`CMD_PORT_MAP`, e.g., `evil-winrm` requires port 5985/5986) and a port scan (`ports.open`) has proven that port is closed on the target.
3. **Unfilled Earned Token (`isGated(c_i, i)`)**: The rendered template `fillCommand(a, F, opts, i)` still contains an unfilled `{{token}}` from `EARNED_TOKENS` (`{{domain}}`, `{{basedn}}`, `{{userlist}}`, `{{hashfile}}`, `{{group}}`, `{{abuse_groups_quoted}}`, `{{flag_path}}`, etc.).
4. **Already Tried in the Current Access Epoch (`commandTriedInEpoch`)**: The command (or an equivalent command sharing the same normalized `commandSignature` on a sibling card, such as `bloodyAD ... get writable` across `bloodyad-acl` and `ad-path-manual`) was already executed in the current $(\text{target}, \text{Epoch}(F), \text{credentialId})$ with a conclusive outcome (`outcome.retireCommand === true`) or a 0-finding result.

Among all remaining eligible, un-settled, un-gated, untried commands matching locus $L$:
- If $a.\text{sequence} = \text{true}$ (an ordered multi-step pipeline such as locate-then-read or join-group-then-grant-dcsync), the **first** live step in authored sequence order is chosen.
- Otherwise (interchangeable tool alternatives), `preferredCommandIndex` selects the first live non-switchless probe backed by `PREFERRED_TOOLKIT` (`nxc`, `impacket-*`, `bloodyad`, `bloodhound-python`, `certipy`, etc.), falling back to authored index order.

### 8.2 Attempt Outcome Classification ([`assets/engine/outcomes.js`](assets/engine/outcomes.js))

When the operator pastes terminal output (or clicks **Ran - Nothing Found**), `OBOL.outcomes.classify` evaluates the text, command, extracted proof facts, and diagnostic blockers into one of seven formal outcome states:

| Outcome Kind (`outcome.kind`) | Condition | `conclusive` / `retireCommand` | Effect on Move & Command |
| :--- | :--- | :---: | :--- |
| **`success` / `duplicate`** | Produced substantive `resultProof` (or authentication proof on a bare validation probe; `duplicate` when confirming facts already held) | `true` / `true` | Mints facts, settles satisfied `settled_by` commands, resets `moveDryTriesInEpoch` to `0`, and promotes the next sequential command to `#1`. |
| **`completed-negative`** | Explicit negative/empty output (e.g., `No entries found`, 0 stdout lines between prompts, `nxc` sub-operation with 0 findings, or `[OBOL: completed with no output / nothing found]`) | `true` / `true` | Retires the tried command in the current `accessEpoch` and increments `moveDryTriesInEpoch` if 0 facts were minted. |
| **`authorization-denied`** | `STATUS_ACCESS_DENIED`, `insufficientAccessRights`, `DSID-0C0907C2` anonymous bind denial | `true` / `true` | Preserves authentication proof (if any), records scoped denial, retires the denied command in the current context. |
| **`rejected`** | `STATUS_LOGON_FAILURE`, `Login incorrect`, `Permission denied (password)` | `true` / `true` | Marks credential validation as `refuted` for that `(host, credentialId, service)` context and retires the command for that credential. |
| **`environment-error`** | `Connection timed out`, `KRB_AP_ERR_SKEW`, `Name or service not known`, `command not found`, active `blocker.*` | `false` / `false` | **Never retires the command and never demotes the card.** Surfaces the matching reactive Fix Doctor card so the operator can repair the environment and retry. |
| **`partial`** | Output truncated (`[output truncated]`), mixed auth, or environment error alongside partial proof | `false` / `false` | Retains all supported facts minted so far while keeping the command and move active (`!settled`). |
| **`parser-error` / `unknown`** | Unrecognized output without completion markers or proof | `false` / `false` | Saves raw output to Run Log without retiring the command or penalizing the move. |

> [!NOTE]
> **Sub-Operation Banner Isolation**: When `nxc` runs a sub-operation (`--shares`, `--users`, `--groups`, `--pass-pol`, `--rid-brute`, `--kerberoasting`, `--asreproast`, `-M <module>`, `-x`, `-X`), its connection banner always prints `[+]` (which mints `smb.null_session` or `*.authenticated`). `outcomes.js` explicitly excludes session/authentication banner facts from `resultProof` whenever `operation` is true, ensuring that an `nxc` sub-operation that authenticates but returns zero findings is classified as `completed-negative` (or `authorization-denied`) rather than a false positive success.

### 8.3 Closed-Loop Dry-Probe Rotation (`moveDryTriesInEpoch` in [`command.js`](assets/engine/command.js) & [`path.js`](assets/ui/routes/path.js))

For a given move $a$, target host $T$, and access epoch $E = \text{Epoch}(F)$, let $\mathcal{H}(a, T, E)$ be the chronological list of activity records in the current epoch matching move $a$ (either directly by `action_id === a.id` or by cross-card `commandSignature` equivalence on a command of $a$):

1. **Productive Reset**: If the most recent activity for $a$ in epoch $E$ produced any non-incidental fact (anything beyond echoed connection/session banners) or settled a `settled_by` command of $a$, then $\text{moveDryTriesInEpoch}(a, F, E, T) = 0$. The move remains at `#1` in `onFlow` and immediately promotes its next sequential command to Command `#1`.
2. **Dry-Probe Increment**: Otherwise, $\text{moveDryTriesInEpoch}(a, F, E, T)$ counts the number of conclusive dry attempts in epoch $E$ (where no new facts were produced, no `environment-error` / `partial` / `blocker.*` occurred, and either `action_id === a.id` or `outcome.retireCommand === true`).
3. **Complete Command Exhaustion (`hasRunnableCommand(a)`)**: If every eligible command on move $a$ is either gated on an unearned fact or has been tried in epoch $E$, `hasRunnableCommand(a)` returns `false` and $a$ leaves `onFlow` until a new fact or new `accessEpoch` unlocks additional commands.
4. **Stable Dry-Count Rotation in `rankFor` ([`assets/ui/routes/path.js`](assets/ui/routes/path.js))**: Among all moves in `onFlow`, OBOL applies a stable partition by `moveDryTriesInEpoch`:

```math
\text{onFlow}_{\text{sorted}} = \text{stableSort}\Big(\text{onFlow},\; (x, y) \mapsto \text{dry}(x) - \text{dry}(y)\Big)
```

Untried hypotheses $(\text{dry} = 0)$ always lead tried-and-dry hypotheses $(\text{dry} \ge 1)$, and the Cockpit UI (`render()` in `path.js`) automatically advances `nsSel.id` to `onFlow[0].id` whenever the previously expanded card has been demoted by a dry probe.

As a result, an operator following the simple rule **"Always run Command `#1` on Card `#1` and paste the output"** is guided smoothly through multi-step enumerations, automatically pivoted past dry probes (such as an empty `bloodyAD get writable` check rotating cleanly to `kerberoast`), and promoted immediately to Tier 4 and Tier 5 cash-ins the instant a hash, credential, ACL lead, or administrative session is earned.
