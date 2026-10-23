# Application Risk Intelligence — PUA, Shadow Software & Offensive Tool Execution | V1

This dashboard turns **SentinelOne Process Creation and file telemetry** into an analyst-focused application governance and threat-hunting view for SOC operations.

## Primary use cases
- Monitor execution of **offensive security / hacking tools**, credential-access utilities, reconnaissance tooling, privilege-escalation utilities, ransomware-operator tools, proxy/tunneling software, and remote-access tooling.
- Identify **Potentially Unwanted Applications (PUA)** and shadow software: VPN clients, P2P/torrent clients, streaming/IPTV software, gaming platforms and games, music apps, chat/collaboration clients, PDF editors/readers, alternative office suites, and alternative browsers.
- Detect **data movement tooling** such as file-transfer clients and cloud-storage / synchronization applications.
- Identify **virtualization, emulation, containers, local AI runtimes, and cryptocurrency miners**.
- Surface tracked applications launched from **user-writable paths** such as Downloads, Temp, Desktop, AppData, /tmp, and user home directories.
- Surface process execution associated with download origins from a curated **freeware / torrent / exploit distribution domain list**.
- Monitor **rare or security-sensitive file extensions** including script, shortcut, disk-image, virtual-disk, installer/package, and AI model-weight formats.
- Pivot from **User → Risk Category → Process** and **Endpoint → Process → Launcher** using Sankey visualizations.
- Provide raw event tables with process path, command line, publisher, signature status, SHA-256, origin location, and Storyline context.

## Triage priority model
This is a **custom SOC prioritization model**, not a SentinelOne threat severity:
- **CRITICAL** — Credential Access, Privilege Escalation, Ransomware Operator Tools, Offensive C2 Frameworks.
- **HIGH** — Proxy/Tunneling/Anonymizers, Pentesting, Reconnaissance, Defense Evasion, Remote Access/Lateral Movement, Cryptocurrency Miners.
- **ELEVATED** — File Transfer, Cloud Storage/Sync, Virtualization/Containers, Local AI, VPN, P2P/Torrent, Illegal Streaming/IPTV.
- **ADVISORY** — Chat, Gaming, Streaming, Music, PDF tools, Alternative Office Suites, Alternative Browsers.

## Important interpretation notes
- **Process-name matching is a governance and hunting baseline, not proof of malicious intent.** Legitimate enterprise software can appear in high-risk categories.
- Attackers can rename binaries. Validate suspicious launches with **path, publisher, signature status, hash, command line, origin URL/path, parent/launcher process, user, and Storyline**.
- Launch counts are **Process Creation events**, not application usage duration.
- Rare file-extension events indicate file activity and **do not by themselves prove execution**.
- Where source detection lists overlapped, this dashboard assigns a **single primary category** to avoid double counting in cross-category visualizations.
- The predefined process baseline contains **911 unique process names** derived from the current application-control hardening catalog available to this project.
- The freeware/torrent/exploit-origin panel uses **50 curated domains** from the current Network Control hardening source list.

## Embedded process coverage
- **Credential Access** — 22 tracked process names. Examples: `AvDump.exe, crackmapexec.exe, hydra-wizard.exe, hydra.exe, john.exe, johnny.exe`
- **Privilege Escalation** — 13 tracked process names. Examples: `GodPotato-NET35.exe, GodPotato-NET4.exe, JuicyPotato.exe, KrbRelayUp.exe, MSFRottenPotato.exe, petitpotato.exe`
- **Ransomware Operator Tools** — 7 tracked process names. Examples: `bleachbit.exe, bleachbit_console.exe, kportscan3.exe, luciroot.exe, Lucirootnew.exe, Stealbit.exe`
- **Offensive C2 Frameworks** — 3 tracked process names. Examples: `CobaltStrike.exe, Empire.exe, ngrok.exe`
- **Proxy / Tunneling / Anonymizers** — 32 tracked process names. Examples: `BlueCoatUnifiedAgent.exe, ccproxy.exe, fiddler.exe, freegate.exe, frpc.exe, gost.exe`
- **Pentesting** — 30 tracked process names. Examples: `adb.exe, armitage.exe, AtomicService.exe, beef.exe, brutus.exe, cewl.exe`
- **Reconnaissance** — 51 tracked process names. Examples: `Adfind.exe, Advanced_IP_Scanner_2.5.4594.1.exe, Advanced_Port_Scanner_2.5.3869.exe, aircrack-ng.exe, arachni.exe, aview.exe`
- **Defense Evasion** — 27 tracked process names. Examples: `avenger.exe, avremover_nt64_enu.exe, backdoor-factory.exe, binaryninja.exe, cutter.exe, gdb.exe`
- **Remote Access & Lateral Movement** — 71 tracked process names. Examples: `AeroAdmin.exe, AmmyyAdmin.exe, AnyDesk.exe, AnyplaceControl.exe, BeyondTrustRemoteSupport.exe, Bomgar-SCC.exe`
- **Cryptocurrency Miners** — 86 tracked process names. Examples: `avianminer.exe, bitminter.exe, bminer.exe, bzminer.exe, ccminer.exe, cgminer.exe`
- **File Transfer Platforms** — 44 tracked process names. Examples: `AndFTP.exe, AnonFiles.exe, AnyClient.exe, BayFiles.exe, BitKinex.exe, ClassicFTP.exe`
- **Cloud Storage & Sync** — 39 tracked process names. Examples: `AirExplorer.exe, AmazonPhotos.exe, Box.exe, BoxSync.exe, bzbui.exe, bzserv.exe`
- **Virtualization / Emulation / Containers** — 49 tracked process names. Examples: `containerd.exe, docker-compose.exe, docker.exe, dockerd.exe, hyperv.exe, lxc.exe`
- **Local AI / Shadow AI** — 10 tracked process names. Examples: `AnythingLLMDesktop.exe, ChatGPT.exe, claude.exe, gpt4all.exe, jan.exe, LM Studio.exe`
- **VPN Clients** — 53 tracked process names. Examples: `AvastSecureLine.exe, Betternet.exe, CheckPointVPN.exe, CiscoAnyConnect.exe, Cloudflare WARP.exe, CyberGhost.exe`
- **P2P / Torrent** — 10 tracked process names. Examples: `azureus.exe, bitcomet.exe, bittorrent.exe, deluge.exe, frostwire.exe, popcorn-time.exe`
- **Illegal Streaming / IPTV** — 6 tracked process names. Examples: `DixMax.exe, IPTVSmarters.exe, Kodi.exe, Stremio.exe, TeaTV.exe, xtreamclient.exe`
- **Chat / Collaboration** — 17 tracked process names. Examples: `Discord.exe, element.exe, ICQ.exe, Line.exe, pidgin.exe, session.exe`
- **Game Platforms / Cloud Gaming** — 45 tracked process names. Examples: `airgpu.exe, amazon-games.exe, antstream-arcade.exe, Battle.net.exe, BethesdaNetLauncher.exe, blacknut.exe`
- **Video Games** — 67 tracked process names. Examples: `ACValhalla.exe, AmongUs.exe, Anthem.exe, ApexLegends.exe, BaldursGate3.exe, BattlefieldV.exe`
- **Streaming / Live TV** — 69 tracked process names. Examples: `AcornTV.exe, ALTBalaji.exe, AppleTV.exe, BeeTV.exe, BigoLive.exe, BritBox.exe`
- **Music / Media Players** — 61 tracked process names. Examples: `AIMP.exe, AIMP3.exe, Amarok.exe, AmazonMusic.exe, APlayer.exe, AppleMusic.exe`
- **PDF Editors / Readers** — 63 tracked process names. Examples: `ABBYYPDFTransformer.exe, AbleWord.exe, AiseesoftPDFEditor.exe, AllPDFEditor.exe, ApowerPDF.exe, AshampooPDF.exe`
- **Alternative Office Suites** — 18 tracked process names. Examples: `DesktopEditors.exe, editors.exe, et.exe, PlanMaker.exe, polarisoffice.exe, Presentations.exe`
- **Alternative Browsers** — 18 tracked process names. Examples: `brave.exe, browser.exe, chrome.exe, chromium.exe, epiphany.exe, falkon.exe`

## Rare / high-interest file extensions
- **Script / execution-adjacent:** `hta, sct, scf, chm, js, jse, vbs, vbe, wsf, wsh, ps1, psm1, psd1, bat, cmd, cpl, scr, com, pif, xll, jar, lnk, reg, inf`
- **Disk images / virtual disks:** `iso, img, vhd, vhdx, vmdk, qcow, qcow2, ova, ovf, dmg`
- **Installers / packages:** `msi, msp, msix, appx, appxbundle, apk, pkg, deb, rpm, appimage`
- **AI model weights:** `gguf, safetensors, pt, pkl, pickle, joblib, onnx, ggml`

## Recommended SOC workflow
1. Start with **Executive Overview** and review Critical/High launch volume.
2. Pivot into **Offensive & Admin Tools** for threat-tooling context.
3. Review **Shadow Apps & PUA** for policy violations and shadow software.
4. Review **Data Transfer & Cloud** for potential exfiltration or unsanctioned synchronization.
5. Use **Virtualization, AI & Compute** for shadow compute and resource-abuse signals.
6. Use **Rare Files & Origins** for suspicious staging, download provenance, and unusual file types.
7. Finish in **Investigation** to collect process-level evidence and Storyline identifiers.

Developed by the Threat Detection Engineering Division at NeverOff Technology (SentinelOne Division)
Dominican Republic
