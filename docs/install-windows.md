# Install on Windows (beta)

The Windows version is a **beta**. It does not promise parity with Linux, and it ships **unsigned** (see [Unsigned beta](#unsigned-beta-what-windows-will-say)). Read this page before you run the installer.

## Requirements

- Windows 10 or 11, 64-bit (amd64). ARM64 is not supported yet.
- The Microsoft WebView2 Runtime. Windows 11 includes it. If it is missing, the installer and the app tell you and give the official link: <https://developer.microsoft.com/microsoft-edge/webview2/consumer/>. MACUAHUITL does not bundle or download anything from Microsoft.
- Installing needs no administrator rights; only the firewall rule for the servers does (once). It installs for your user only.
- A standard account, or an administrator account with UAC on. With UAC off or with the built-in Administrator account, the core refuses to start.

## Download and verify before you run it

From the [latest release](../../../releases/latest), download the installer and `SHA256SUMS`. The installer is named `MACUAHUITL-<version>-setup.exe`; the exact name is on the release page.

The release also has `macuahuitl_<version>_windows_amd64.zip`, with the same three programs and the license files and no installer. This guide covers the installer.

Check the hash in PowerShell, in the folder you downloaded to, and compare it with the line for your file in `SHA256SUMS`:

```powershell
(Get-FileHash -Algorithm SHA256 .\MACUAHUITL-<version>-setup.exe).Hash.ToLower()
```

`Get-FileHash` prints capital letters and `SHA256SUMS` uses lowercase; `.ToLower()` makes them match.

With Git Bash you can use `sha256sum -c --ignore-missing SHA256SUMS` instead.

The hash catches a broken download. To check that the file was built by this repository's release workflow, verify its signed provenance with the [GitHub CLI](https://cli.github.com/):

```powershell
gh attestation verify .\MACUAHUITL-<version>-setup.exe --repo oom-netsec/MACUAHUITL `
  --signer-workflow oom-netsec/MACUAHUITL/.github/workflows/release.yml
```

Do not run an installer that fails either check.

## Unsigned beta: what Windows will say

The beta has no code signature. Verification relies on `SHA256SUMS`, the attestation above and the open source code. This has consequences:

- **SmartScreen** shows "Windows protected your PC". Choose **More info**, then **Run anyway**. It comes back with every new version.
- **Smart App Control** (Windows 11), if it is on, blocks an unsigned executable completely, with no option to run it. Depending on your Windows 11 version, turning it back on may require reinstalling Windows. That decision is yours; the project does not recommend it.
- **Microsoft Defender** may flag an unsigned Go binary as a false positive. If it does, report it to Microsoft as a false positive.

## What it installs and where

- **Program:** `%LOCALAPPDATA%\Programs\MACUAHUITL` (the app, the core `macuahuitld.exe`, `mctl.exe` and the license files).
- **Shortcuts:** one in the Start menu. A desktop shortcut is optional and off by default.
- **Startup:** the core starts when you log in, through a `Run` entry in `HKCU`. Nothing is written to `HKLM` and there is no Windows service.
- **Core log:** `%LOCALAPPDATA%\MACUAHUITL\state\macuahuitld.log`, useful for support.
- **Data** (vault, audit log, settings): `%LOCALAPPDATA%\MACUAHUITL`.
- **Outputs** (evidence, captures): `%USERPROFILE%\MACUAHUITL\outputs`.

If the installer is started as administrator, it warns you: run it again without "Run as administrator".

## Content packs

Playbooks come in content packs (`.mpack`), published with each release. Install the ones you need in **Settings → Packs → Install pack…**, or with `mctl`. The installer does not add `mctl` to `PATH`, so call it by its path. `cmd.exe` does not expand `*`, so give the full file name (with the version of the file you downloaded), from the folder you downloaded it to:

```bat
"%LOCALAPPDATA%\Programs\MACUAHUITL\mctl.exe" pack install oom-ios-xe-1.1.4.mpack
```

In PowerShell, to install every official pack in the current folder:

```powershell
Get-ChildItem oom-*.mpack | ForEach-Object { & "$env:LOCALAPPDATA\Programs\MACUAHUITL\mctl.exe" pack install $_.FullName }
```

## Firewall and ports

Windows has no privileged ports, so the TFTP, FTP, SCP/SFTP, syslog and trap servers listen on their standard ports. What stands in the way is Windows Firewall.

For TFTP, FTP and SCP/SFTP the app shows the exact `New-NetFirewallRule` command for the server you start, limited to the core program, the IP, the protocol and the port. Run it once in an administrator PowerShell. The app never applies it for you. Copy the one the app shows, which has your path and IP. It looks like this, for a TFTP server on 10.0.0.5:

```powershell
New-NetFirewallRule -DisplayName 'MACUAHUITL tftp 10.0.0.5 69' -Direction Inbound -Program 'C:\Users\<you>\AppData\Local\Programs\MACUAHUITL\macuahuitld.exe' -LocalAddress 10.0.0.5 -Protocol UDP -LocalPort 69 -Action Allow
```

The app also shows the `Remove-NetFirewallRule` command to remove it when you are done. For FTP the rule also opens the passive port range. Instead of the rule, accepting the Firewall dialog that appears the first time a server listens also works, but it also asks for administrator credentials.

For syslog (UDP 514) and traps (UDP 162) the app does not show a command: create an equivalent rule yourself or accept the Firewall dialog.

If you cancel the Windows Firewall dialog the first time a server listens, Windows creates **block** rules for the program, and block rules win over allow rules. Remove them in *Windows Defender Firewall with Advanced Security → Inbound Rules* (look for `macuahuitld.exe`), then add the allow rule.

## Optional tools you install yourself

These are never part of the installer:

- **nmap** and **Wireshark with Npcap** (packet capture), and **iperf3**. Without them each tool shows an install message with the download link.
- The SYN scan option of nmap is hidden on Windows; scans use a normal connection.
- For serial console you need the USB driver of your adapter.

## What may be missing in the beta

- Packet capture, until you install Wireshark with Npcap (nmap and iperf3 likewise).
- Locking all of the process memory: only the ranges that hold key material are locked.
- Protection against other processes of the same user, which does not exist on Windows without administrator rights.
- The serial console, if its validation on real hardware is not ready: it is marked "not validated".
- ARM64: amd64 only at first.
- The nmap SYN scan.

Everything else is meant to work as on Linux, including the vault, Patrol, assisted change, `.mpack` packs, masking, the audit log and the SSH terminal. That is the bar the Windows tests hold, not a guarantee.

## Update

Run the new installer over the old one. It asks the core to stop first. If work is in progress (a Patrol job, a transfer or a capture), it tells you and changes nothing: finish or cancel the work and try again. If the app is open, close it first.

## Uninstall

Close the app first, then use *Settings → Apps* and remove MACUAHUITL. If work is in progress, the uninstall stops and changes nothing, as when updating. The uninstaller removes only what the installer put there.

- Your data in `%LOCALAPPDATA%\MACUAHUITL` is deleted only if you answer **Yes** to a separate question. The default is **No**, and a silent uninstall (`/S`) never deletes it.
- The outputs folder is never deleted.
