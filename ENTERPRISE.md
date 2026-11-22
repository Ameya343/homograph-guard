# Deploying Homograph Guard in an organisation

Homograph Guard is built to be deployed where email privacy matters: everything
runs on the employee's device, nothing is sent to us or to any cloud service,
and an administrator can lock the privacy-relevant settings. This page covers
the policy file, network requirements, proxies and TLS inspection, offline
mirrors, packaging for each platform, and the browser extension.

## At a glance

- **Checks run on the device.** The browser extension hands links to the app
  over native messaging; the threat database and the lists are local SQLite.
- **No content leaves the device.** Not the email, not the page, not the full
  link. With the default `dns_mode: off`, the extension makes no network
  request at all. See [SECURITY.md](SECURITY.md#privacy) for every case.
- **One outbound job:** the daily download of public threat lists, through your
  proxy if you have one, or from your own mirror.
- **No listening ports, no admin rights** for normal use; the Windows firewall
  rules are optional.

## Policy file

An administrator places a JSON file where users cannot change it:

| Platform | Location |
| --- | --- |
| Windows | `%ProgramData%\HomographGuard\policy.json` |
| macOS | `/Library/Application Support/HomographGuard/policy.json` |
| Linux | `/etc/homograph-guard/policy.json` |

Make it readable by users and writable only by administrators (the default for
those folders when an administrator creates the file). Every key the policy sets
is locked: the app, the GUI and the extension show it as "set by your
organisation", and attempts to change it are refused.

| Key | Value | Effect |
| --- | --- | --- |
| `dns_mode` | `"off"`, `"suspicious"` or `"all"` | Whether the extension's checks may ask public DNS resolvers. `"off"` keeps every check on the device. |
| `short_links` | `"app"`, `"browser"` or `"off"` | Who may ask link-shortening services where a short link leads. `"app"` (default): the app and CLI (with DNS checks on, never by themselves for links in mail and chat) and, for services that answer only browsers, the user's browser when the user chooses "Show where this short link leads". `"browser"`: only the browser, on request (when only the browser may reach the internet, through your proxy). `"off"`: nobody; short links stay a Caution. |
| `feeds` | `{"openphish": false, ...}` | Turn individual feeds on or off (see licences below). |
| `proxy` | `"http://proxy.corp.example:8080"` | Proxy for the updater (otherwise the system or environment proxy is used). |
| `cafile` | `"/path/corp-root.pem"` | Extra trusted root, e.g. your TLS-inspection CA, for the updater. |
| `feed_mirror` | `"https://mirror.corp.example/feeds/"` | Download `<feed>.txt` from your server instead of the internet (policy only). |
| `update_hour` | `0`-`23` | Hour of the first daily attempt when `setup schedule install` runs; retries follow hourly (policy only). |
| `allow` | `["partner-portal.example", ...]` | Organisation allowlist (domains or links), merged with each user's own. |
| `block` | `["https://evil.example/login", ...]` | Organisation blocklist, merged with each user's own. |

Example:

```json
{
  "dns_mode": "off",
  "short_links": "browser",
  "proxy": "http://proxy.corp.example:8080",
  "cafile": "/etc/ssl/certs/corp-tls-inspection.pem",
  "feeds": {"openphish": false, "phishing-army": false},
  "allow": ["corp-sso.example", "partner-portal.example"],
  "block": ["corp-blocked-example.com"]
}
```

Unknown keys and invalid values are ignored, so a typo never disables the app;
files over 1 MB are ignored. Check the effective settings with
`homograph-guard settings show`.

## Network requirements

| Who | Destination | When |
| --- | --- | --- |
| Updater (`hg-update.exe`, or `homograph-guard update`) | HTTPS (TCP 443) to `raw.githubusercontent.com`, `malware-filter.gitlab.io`, `hole.cert.pl`, `phishing.army` (also allowed: `openphish.com`, should its feed redirect there, and `adguardteam.github.io` if that feed is turned on) | once a day; or only your `feed_mirror` |
| App, browser helper and CLI, DNS checks | TCP 443 to the pinned resolver addresses: 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 1.1.1.2, 1.0.0.2, 94.140.14.140, 94.140.14.141, 94.140.14.14, 94.140.15.15 (and their IPv6 addresses) | only if `dns_mode` allows it, or when a user checks a link by hand without `--no-dns` |
| Extension without the app, DNS checks | HTTPS to `dns.google`, `cloudflare-dns.com`, `security.cloudflare-dns.com`, `dns.adguard-dns.com`, `unfiltered.adguard-dns.com` through the browser (and its proxy) | only if `dns_mode` allows it |
| App and CLI, short links | TCP 443 directly to the shortening service of the link (bit.ly, tinyurl.com, shorturl.at, t.co, is.gd, ...), at the address the pinned resolvers give | with DNS checks on, for links checked by hand (not links in mail or chat unless `--expand-in-messages`); with `short_links: "app"` |
| Browser, "Show where this short link leads" | HTTPS to that shortening service and `challenges.cloudflare.com`, through the browser (and its proxy); nothing else from that tab | only when a user chooses it; not with `short_links: "off"` |

The app's DNS checks go directly to the pinned addresses, never through a proxy
(so a compromised network cannot answer for the resolvers). If your firewall
allows only the proxy, DNS checks report "unavailable" within a second and every
other check still works; keep `dns_mode: "off"`, or allow TCP 443 to the
addresses above. The same goes for short links: if the app cannot reach a
shortening service, the extension asks through the browser instead (or set
`short_links: "browser"` to skip the app's attempt). For mail gateways that scan
on delivery, `homograph-guard --eml message.eml --expand-in-messages` also
expands the short links in the message: the sender learns nothing new then.

### Proxies and TLS inspection

The updater uses `proxy` (or the system and `HTTPS_PROXY` settings) and verifies
TLS against the system store plus `cafile`. If a TLS-inspecting proxy re-signs
the feed servers' certificates with a root the device does not trust, the
update is refused with *"TLS certificate not trusted (a proxy may be inspecting
TLS: add its CA with --cafile or the cafile setting)"* and the previous data is
kept. Distribute only the public root certificate, never its private key.

### Air-gapped networks: your own mirror

Set `feed_mirror` to an HTTPS folder on your network that serves the feeds as
`<name>.txt`, in the same format as the original URLs (`homograph-guard db
status` lists the names, `src/homograph_guard/feeds.py` the URLs). Fetch them on a machine
with internet access, check them, and copy them to the mirror on your own
schedule. With a mirror, clients contact only the mirror, over HTTPS, trusting
your `cafile`.

### Feed licences

`openphish` (OpenPhish community licence) and `phishing-army` (CC BY-NC 4.0)
are for non-commercial use. Unless you have a licence, turn them off in the
policy (`"feeds": {"openphish": false, "phishing-army": false}`) or replace them
with licensed data through your mirror. `phishing-filter` and `urlhaus-filter`
are CC0, `cert-pl` is CERT Polska open data, and `hagezi-tif` is GPL-3.0.

## What crosses the network

The enterprise lab (`bash labs/enterprise/run.sh`) puts the hardened app on a
network with no direct internet and a TLS-inspecting proxy (mitmproxy) as the
only way out, and records every request the proxy sees. A complete run, from a
refused update without the company root, through a full update with it, to
checks of links, saw exactly this:

```text
   1 x GET hole.cert.pl
   2 x GET malware-filter.gitlab.io
   1 x GET phishing.army
   2 x GET raw.githubusercontent.com
  request headers sent: accept, accept-encoding, connection, host, user-agent
  user agents: ['homograph-guard/1.2.0 (feed updater)']
  query strings: none
  request bodies: 0 bytes
  TLS handshakes the app refused (untrusted proxy certificate): 2
```

No link that was checked, no user or device information, no cookies. The same
run confirms that a locked setting cannot be changed, that the organisation's
lists apply, that blocked DNS-over-HTTPS degrades in about a second, and that an
air-gapped client updates from an internal mirror.

## Windows

The installer (`HomographGuard-Setup-<version>.exe`) installs per user into
`%LOCALAPPDATA%\Programs\HomographGuard` and needs no administrator rights.
Deploy it in the **user context** (for example Intune "Install behavior: User"):

```text
HomographGuard-Setup-1.3.0.exe /S [/FIREWALL] [/NOSHORTCUTS] [/NOEXTENSION] [/NOUPDATES]
"%LOCALAPPDATA%\Programs\HomographGuard\Uninstall.exe" /S [/PURGE]
```

- `/NOEXTENSION` skips registering the browser helper; `/NOUPDATES` skips the
  daily task and the first download; `/FIREWALL` adds the firewall rules (it
  asks for administrator rights once).
- Interruptions are safe: the new version is unpacked into `HomographGuard.new`
  and swapped in with two folder renames, so the program folder always holds a
  complete version. Every step can be repeated, so re-running the same command
  (for example from your deployment tool's retry) finishes an interrupted
  installation; `InstallState` in `HKCU\Software\HomographGuard` reads
  `complete` when it did. Setup never registers itself to run at sign-in, which
  heuristic antivirus engines treat as persistence. `/D=` must name a new or
  empty folder (or the existing installation).
- Sign `HomographGuard-Setup-<version>.exe` and the programs inside it with your
  organisation's code-signing certificate before deployment (for example
  `signtool sign /fd sha256 /tr <timestamp URL> /td sha256 ...` on the PyInstaller
  output before `makensis` runs, then on the installer). Unsigned installers are
  more likely to trip reputation and machine-learning antivirus checks.
- The daily task runs as the user with least privilege. It starts at the
  configured hour and repeats every hour for 12 hours, plus 10 minutes after
  sign-in; each run downloads only what is due (older than 20 hours, or failed
  and past its back-off), so the repeats cost nothing once the update worked.
- `homograph-guard native-host install --machine` registers the helper in HKLM
  for every user (administrator rights), if the program is in a folder every
  user can read.

### Windows firewall rules

The optional rules (`homograph-guard setup firewall show --install-dir DIR`
prints them as `netsh` commands) restrict each program to what it needs:

| Program | Inbound | Outbound |
| --- | --- | --- |
| `HomographGuard.exe` (window) | blocked | blocked (it never needs the network) |
| `hg-native-host.exe` (browser helper) | blocked | only the pinned DNS resolvers, only on DNS ports (53, 443, 853) |
| `homograph-guard.exe` (command line) | blocked | only the pinned DNS resolvers, only on DNS ports |
| `hg-update.exe` (updater) | blocked | TCP 80, 443, 3128, 8080, 8443 only (proxies included), no UDP |

Add your proxy's port with `setup firewall install --updater-port 9090`. The
rules are block rules, so they work alongside your own policy and never open
anything. `setup firewall uninstall` (or uninstalling the app) removes them.

## macOS and Linux

Install the Python package into a folder users cannot change (for example a
virtual environment in `/opt/homograph-guard` owned by root), then:

```bash
sudo /opt/homograph-guard/bin/homograph-guard native-host install --machine
```

This registers the helper for every user in the browsers' system folders
(Chrome, Edge, Chromium and Firefox; Brave documents no system folder, so
register it per user with `native-host install --browser brave`).

| Browser | macOS (all users) | Linux (all users) |
| --- | --- | --- |
| Chrome | `/Library/Google/Chrome/NativeMessagingHosts` | `/etc/opt/chrome/native-messaging-hosts` |
| Edge | `/Library/Microsoft/Edge/NativeMessagingHosts` | `/etc/opt/edge/native-messaging-hosts` |
| Chromium | `/Library/Application Support/Chromium/NativeMessagingHosts` | `/etc/chromium/native-messaging-hosts` |
| Firefox | `/Library/Application Support/Mozilla/NativeMessagingHosts` | `/usr/lib/mozilla/native-messaging-hosts` |

Each user has their own database and lists, so the daily update runs per user.
`homograph-guard setup schedule show` prints exactly what `setup schedule install`
would create, so you can deploy it for everyone instead:

- **Linux:** put the two printed units in `/etc/systemd/user/` and run
  `systemctl --global enable homograph-guard-update.timer`; each user's own
  systemd then runs it. The service is sandboxed (`NoNewPrivileges`,
  `@system-service` system-call filter, `RestrictNamespaces`, `UMask=0077`)
  without needing user namespaces.
- **macOS:** put the printed plist in `/Library/LaunchAgents/`; launchd starts
  it in every user's session.

Snap and Flatpak browsers may not be allowed to start the helper; the extension
then checks in the browser on its own.

## Browser extension

The extension's ID is fixed for unpacked installs (`lfcmpmjjgdljkicfeikalojnocghgibe`
in Chromium browsers, `{b8a89689-dc16-48f4-936e-100f254404d8}` in Firefox), and
the helper accepts only those IDs.

**Chrome and Edge.** Publish the extension privately in the Chrome Web Store or
Edge Add-ons, or host a packed `.crx` with an update manifest, and force-install
it with the `ExtensionInstallForcelist` policy (`<id>;<update URL>`). The store
or your packing key gives it a new ID: allow it with

```bash
homograph-guard native-host install --machine --extension-id <id>
```

Restrict where it may read pages, if needed, with `ExtensionSettings` →
`runtime_blocked_hosts` (for example internal HR or finance systems).

**Firefox.** Sign the extension on addons.mozilla.org as unlisted (`web-ext
sign`), host the `.xpi`, and deploy it with `policies.json`:

```json
{
  "policies": {
    "ExtensionSettings": {
      "{b8a89689-dc16-48f4-936e-100f254404d8}": {
        "installation_mode": "force_installed",
        "install_url": "https://intranet.corp.example/homograph-guard.xpi"
      }
    }
  }
}
```

The Firefox ID stays the same when signed, so the helper needs no change.

## Verifying a deployment

```bash
homograph-guard settings show          # effective settings and which ones your policy locks
homograph-guard db status              # database age, size and feed status
homograph-guard native-host status     # where the helper is registered
homograph-guard setup schedule status  # the daily update
```

In the browser, the extension's **Options** page shows whether the app is
connected, the organisation's lists, and the DNS setting as locked when the
policy sets it.
