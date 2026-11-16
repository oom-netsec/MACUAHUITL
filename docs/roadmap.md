# MACUAHUITL roadmap

Mission: put a TAC on every engineer's laptop, useful for **all** daily work and not only for reading. Flow: **collect → search → analyze → correlate → change safely → report**.

Principles: local first and audited, secrets in the vault, no false "all clear", permissive licenses and no privileged code. Reading and analyzing are free. **Changing the network** goes through the [assisted change mode](adr/0007-modo-cambio-asistido.md): visible command, confirmation, pre/post-check, rollback and audit.

## Done up to v1.0.0

| Area | What's included |
|---|---|
| Base | Core, vault, chained audit log, Patrol, CLI and app (phases 0–6) |
| Tools | PCAP analyzer, light and deep DNS, TLS inspector, syslog receiver (7) |
| Analysis | 44 analysis rules, diff between rounds, correlated timeline; in the app, "Job analysis" (9) |
| Field and transfers | Serial console, temporary TFTP/HTTP/FTP/SCP/SFTP servers and clients, MD5/SHA-512 (10, 22a) |
| Changes | Pre/post with a traffic-light verdict, upgrade assistant (verification), golden templates and hardening (11) |
| Visibility | CDP/LLDP topology (SVG), SNMP and traps, NetFlow/IPFIX/sFlow, gNMI (12) |
| Calculators | Subnets/VLSM, MTU/MSS, TCP, QoS, optics, BGP path selection (13) |
| Security | RADIUS/TACACS+ probes, lab PKI, IKE/IPsec decoder (14) |
| ACL | Import, analysis (shadowed, redundant) and IOS-XE/NX-OS/ASA translation (5) |
| Fleet | Global search, L2 tracing, L3/L2 path, interface health, morning check, flash/DRAM, inventory (15) |
| Operations | Assisted change mode, read-only batches, snippets, port provisioning, backup and restore, drift, Cleaner, credential rotation, multi-tab SSH terminal and saved hosts (16) |
| Forensics | Crashinfo, Cisco message database, silent flapping, syslog patterns, debug filter, memory leaks across rounds (17) |
| Content packs | 11 signed official packs (≈600 playbooks), install preview, hide per item, personal pack, `packs-YYYY-MM-DD` releases; an official pack displaces a colliding third-party pack only after confirmation ([ADR 0010](adr/0010-paquetes-de-contenido.md)) |
| Language | English is canonical in the app, core and `mctl`; Spanish in Settings and with `--lang es` |
| Lab | Read-only runs with `tools/labcheck` on a 3560CX, a 9120 EWC and a Catalyst 9000v (DevNet) (v0.5.0), and in Cisco Modeling Labs: ASAv with A/S failover, Catalyst 8000v and IOSvL2 (v0.5.4); the 21 write templates applied, verified and rolled back on lab devices, CML and the 3560CX (v0.5.4, v0.6.4) |
| Patrol and analysis | Each command runs once per device and round even if several playbooks ask for it (v0.6.0); routing detections (EIGRP, LDP, track, GLBP/VRRP, duplicate OSPF router-id, BGP without prefixes), shared segments in the topology and noise-free diff between rounds (v0.6.1, v0.6.2) |
| Masking and assisted mode | Masking of quoted content, of `backup diff` and drift, of negated lines, of the terminal, of logs that quote commands, of syslog and of abbreviations, with a warning on unmasked evidence (v0.5.2–v0.6.5); `snmp-trap-host` and `netflow-export` templates; templates do not cut the session's port and an unknown `%` error stops the apply; pending rollbacks in the app, also for credential rotation; `change diff` and capture wait; first ASA login detected (v0.5.1–v0.6.5) |
| Robustness | App published with the Wails `production` tag; each command stores at most 64 MiB (v0.6.5) |
| Hardening for 1.0 | Two security audits and a final independent review with every finding closed; masking never shows less than v0.6.5 (v0.6.6–v0.7.1); assisted changes find the session's port also through a management VRF; Patrol reconnects after a cut command and marks the device partial (v0.7.0); signed build provenance for every release file (v0.7.0); full masking corpus under `-race` and long fuzzing nightly and before each release |

## Open after 1.0.0

**Lab validation** of the packs with real devices, following the [runbook](plans/validacion-labs.md) and `tools/labcheck` (per-playbook report). Today only `oom/ios` is validated end to end (3560CX); the `oom/wlc-9800` commands were checked on a 9120 EWC, those of `oom/ios-xe`, `oom/cat9k` and `oom/sda` on a Catalyst 9000v (and `oom/ios-xe` also on a Catalyst 8000v) and those of `oom/asa` on an ASAv. Still pending: `oom/wlc-9800` on a chassis 9800 or 9800-CL, `oom/sda` on a real fabric, `oom/cat9k` on physical hardware (stack, StackWise Virtual, PoE), `oom/ios-xe` with a license level (crypto VPN, MPLS), `oom/asa` in multi-context and cluster, `oom/nx-os` (DevNet) and the platforms without a lab so far. Whatever fails is fixed in the pack and published as a `packs-*` release.

## Cross-cutting prerequisite: real evidence

Everything that reads device output needs real transcripts to be validated. Source: the [lab test battery](plans/laboratorio-bateria-de-pruebas.md). The NX-OS, ASA and other platform packs are already published with commands from Cisco documentation; validating them on real devices is still open.

## Phases

Each phase is a branch and a PR, with its plan in `docs/plans/`, TDD, independent review and at most 2–3 agents at a time.

Phases 15 (fleet), 16 (operations) and 17 (forensics) are already done (see above). The ones that follow come after 1.0.0.

### Phase 18 — L3/L7 PCAP engine and frame generator
1. **Streaming of multi-GB captures** with bounded memory and cancellation.
2. **TCP streams**: handshake latency, retransmissions per hop, RST storms and window exhaustion.
3. **L2/L3 frame generator** (Ethernet/IP/UDP/TCP/GRE) to test ACL, QoS and CoPP. It goes through assisted mode and requires the user to grant the capability to the binary (ADR 0004).
With gopacket (BSD-3). tshark/Wireshark are not embedded (GPL).

### Phase 19 — L2/L3 state and network map
1. **STP debugger**: root and instability, blocked ports and potential loops.
2. **CEF/FIB and asymmetry**: validates the phase 15 path against the data plane.
3. **Orphan VLANs and ports**: nonexistent VLANs, forgotten legacy configuration and inactive ports.
4. **SPOF and failure domains**: port-channels, HSRP/VRRP, stacks and power supplies ("if this cable goes down, you isolate floor 3").
5. **Interactive L2/L3 map** in React and **export to draw.io and Mermaid** (Visio via draw.io).
6. **Light IPAM**: IPs in use per subnet from ARP/DHCP, conflicts and free addresses.

### Phase 20 — Hardware and platform
1. **SFP and DOM**: power levels, temperature, trend and degradation (dirty connectors, bends) before CRCs. OTDR `.sor` files if there is demand.
2. **Cable test** (`test cable-diagnostics tdr`) through assisted mode, with the result read back.
3. **PoE**: budget per switch and ports that do not receive power.
4. **TCAM and ASIC resources**: ACL, QoS, FIB and MRIB at 85 % or more, before silent drops.
5. **Buffers and microbursts**: queue drops and shared buffers.
6. **Image and license requirements**: DRAM/flash of the chosen image and Smart Licensing state.

### Phase 21 — Changes with method
1. **MOP generator**: step-by-step document from the pre-checks, with commands, risks, verification and rollback; it is run with assisted mode.
2. **Rollback**: suggests the inverse script on a regression and applies it with assisted mode.
3. **Configuration linter** (local dry-run) for IOS, IOS-XE and NX-OS before running.
4. **Corporate policies** in golden templates: names, SNMP, NTP and logging.
5. **ACL Match Tracer**: given a tuple (source, destination, port, protocol), which line permits or blocks it on IOS, NX-OS or ASA.

### Phase 22 — Upgrades and transfers
1. **SFTP and FTP servers** (SCP if it fits) next to TFTP/HTTP; encrypted folder for images and backups.
2. **Image repository** with metadata, hashes (adds SHA-1/SHA-256) and tested compatibility.
3. **Extended pre-flight**: DRAM, licenses and flash in batch.
4. **Upgrade execution** (copy, verify, boot, reload) over SSH or console, in assisted mode, with live progress.
5. **Console boot monitor**: boot loops, missing file, ROMMON.
6. **Automatic post-checks** after the reload (reuses pre/post).
7. **Local RADIUS/TACACS+ server** to validate AAA in the field.

### Phase 23 — Advanced routing
1. **L3 policy validator**: route-maps, prefix-lists, as-path and mutual redistribution.
2. **Multicast**: PIM, IGMP, MSDP, RPF failures and orphan states.
3. **BGP convergence and blast radius** (PIC, Add-Paths, path hiding).
4. **GIR**: isolate and reinsert a node (gshut, max-metric, overload bit) with assisted mode.

### Phase 24 — MPLS, Segment Routing and VPN
1. **LDP/SR label continuity (SR-MPLS/SRv6)** through FIB/LFIB.
2. **L2VPN/L3VPN**: RT/RD symmetry, VPLS and MP-BGP.
3. **EVPN-VXLAN and SD-Access**: type 2, 3 and 5 routes and MAC-IP bindings.
4. **IPsec/GRE/VXLAN tunnels** in one view (ikedec + MTU calculator + state).

### Phase 25 — Design and resilience (CCDE mode)
1. **Failure domain simulator**: primary RP, StackWise/VSS/vPC keepalive, split-brain.
2. **What-if** before a maintenance window.

### Phase 26 — Reports and collaboration
1. **TAC packager** with masking of passwords, public IPs and customer data, encrypted.
2. **Forensic incident report** from the timeline.
3. **Executive report** in Markdown/PDF.
4. **Notes per device and per case**, linked to the evidence.
Defined together with the **lead view** from the [backlog](backlog.md).

### Phase 27 — Extensibility and telemetry
1. **Starlark plugins** (starlark-go, BSD-3) in a sandbox. Embedded Python ruled out.
2. **YANG model telemetry** with high-resolution dashboards over gNMI.
3. **Temporary EEM**: injects a capture applet with automatic removal, through assisted mode.

## Content packs by technology

The playbooks and scripts for each technology are published as signed `.mpack` packs ([ADR 0010](adr/0010-paquetes-de-contenido.md)), and each person installs only the ones they use. All are published; they are attached to every app release and to the `packs-*` releases:

| Pack | Playbooks | Lab validation |
|---|---:|---|
| `oom/ios` (classic IOS) | 52 | Validated (3560CX) |
| `oom/ios-xe` (IOS-XE switches and routers) | 69 | Commands checked on Catalyst 9000v (DevNet) and Catalyst 8000v (CML) |
| `oom/cat9k` (Catalyst 9000) | 55 | Commands checked on Catalyst 9000v (DevNet); stack, StackWise Virtual and PoE need physical hardware |
| `oom/sda` (SD-Access) | 26 | Commands checked on Catalyst 9000v (DevNet) without a fabric; a real fabric is missing |
| `oom/wlc-9800` (Catalyst 9800 and EWC) | 47 | Commands checked on a 9120 EWC (17.12.6a); a chassis 9800 or 9800-CL is missing |
| `oom/wlc-aireos` (AireOS) | 64 | Pending |
| `oom/nx-os` (Nexus) | 68 | Pending (DevNet NX-OS) |
| `oom/aci` (ACI leaf and spine) | 45 | Pending |
| `oom/asa` | 68 | Commands checked on ASAv (single context and A/S failover, CML); multi-context and cluster pending |
| `oom/ftd` (Firepower Threat Defense) | 64 | Pending |
| `oom/ise` | 36 | Pending |

## After 1.0.0: Windows and macOS

Starts after 1.0.0 (owner's decision: Linux first, without bugs or vulnerabilities). Today MACUAHUITL is Linux only. The core and `mctl` (Go) and the app (Wails + React) are mostly portable; what is specific to Linux has to be adapted. Windows first, then macOS.

1. **Cross-platform ADR, before touching code**: which features may be missing at first, how it is installed and signed on each system and which code stays per platform (like `internal/sys`).
2. **Linux pieces to adapt**:
   - the local channel between core and clients (today a Unix socket with `SO_PEERCRED`);
   - the memory hardening in `internal/sys` (`mlock`, no core dumps);
   - inhibiting suspend (systemd-logind → `SetThreadExecutionState` / `IOPMAssertion`);
   - serial console (`/dev/ttyUSB*` → `COMx` / `/dev/cu.*`);
   - redirection of ports 21/69 (today `nft`): the server stays on a high port and the equivalent for each system is explained (ADR 0004);
   - external tools (`dumpcap`, `nmap`, `iperf3`, `tracepath`) and their equivalents;
   - core startup (systemd user service → logon task / LaunchAgent).
3. **Installers and signing**: on Windows, an installer signed with a code-signing certificate (SmartScreen also depends on the certificate's reputation); on macOS, a `.dmg` signed with Developer ID and notarized (Gatekeeper, Apple Developer account).
4. **CI and release** with Windows and macOS runners: tests and artifacts for the three platforms on every tag.

## What changes the network and where

Everything goes through the assisted change mode (ADR 0007), built in phase 16.

| Feature | Phase |
|---|---|
| Snippets on one or several devices, port provisioning, restore, credential rotation | 16 |
| Frame generator | 18 |
| TDR cable test | 20 |
| Executed MOP and rollback | 21 |
| Executed upgrade | 22 |
| GIR | 23 |
| Temporary EEM | 27 |
