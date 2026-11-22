# Security model

homograph-guard handles hostile input by design: every link it sees may be a
phishing page, an exploit kit or a malformed string built to break parsers.
This document lists what it does to stay safe, what it keeps private, and where
those guarantees end. Deployment in an organisation is covered in
[ENTERPRISE.md](ENTERPRISE.md).

## What the tool never does

- **It never opens the link.** No HTTP request is ever made to the suspect
  host. The only optional contact is `--tls-peek` (off by default, never for a
  link found in an email or chat), which performs a TLS handshake to read the
  certificate and sends no HTTP at all.
- **Short links: only the shortening service is asked.** For a link on a known
  shortening service (bit.ly, shorturl.at, ...), one `GET` per short link goes to
  that service (address from the pinned resolvers, public addresses only, verified
  TLS, honest User-Agent, no cookies); the `Location` header or a meta refresh in
  the first 64 KB is read and the connection closed. The redirect is never
  followed: the destination is only analysed. Services that answer only browsers
  are reported as such; the tool does not try to get past a bot check. Not done
  by itself for links in emails and chats (see [Privacy](#privacy)).
- **It never uses your system resolver.** DNS questions go to fixed resolver
  IP addresses (Google, Cloudflare, AdGuard, optionally Quad9), so the local
  network cannot answer on their behalf and the suspect name is not leaked to
  your ISP resolver.
- **It never renders content.** The CLI escapes control, bidi and invisible
  characters before printing; the GUI shows plain text in Tk widgets; JSON
  output is ASCII-only.
- **It never connects to private addresses** for `--tls-peek` (no SSRF into
  your LAN), even if the suspect domain resolves to one.
- **It never listens on the network.** No component opens a server socket: the
  browser helper talks to the browser over stdin/stdout, the GUI to its worker
  over pipes. The guard refuses `bind()`, and the optional Windows firewall
  rules block inbound traffic to every program as well.
- **It sends nothing about you.** No telemetry, no account, no crash reports.
  The page, the email and the full link never leave the device; with DNS checks
  switched on, only host names are looked up (see [Privacy](#privacy)).

## Layers of isolation

1. **Parsing as data.** URLs are parsed with a WHATWG-style parser written for
   this tool. There is no `eval`, no shell, and links are passed to worker
   processes on stdin, never on the command line.
2. **In-process guard** (`guard.py`, PEP 578 audit hooks). Once installed it
   blocks process creation, `ctypes`, file writes (except an explicit
   allow-list such as the `--output` file or the settings file), creating
   folders, changing permissions, renames outside the allow-list, system DNS
   lookups, web browsers, `urllib` (except in the updater), SQLite extension
   loading, opening any database but the app's own, binding sockets, and any
   connection that is not to an allow-listed `(ip, port, protocol)`. Audit hooks
   are a guardrail against bugs and malicious dependencies, not a security
   boundary on their own.
3. **Isolated interpreters.** Every launcher runs Python with `-I -B`, so
   `PYTHONPATH`, `PYTHONSTARTUP`, user site-packages and the current folder
   cannot inject code. The bundled Windows programs ignore those variables too
   (tested).
4. **Container** (`Dockerfile` + `sandbox/run.sh`): read-only root filesystem,
   all capabilities dropped, `no-new-privileges`, non-root user, PID, memory
   and CPU limits, no host mounts, `pip` removed from the image, and
   `--network none` for offline checks.
5. **Host egress firewall** (`sandbox/egress-firewall.sh`, Linux): a dedicated
   Docker network whose containers can reach only the pinned resolvers, and
   not the host itself. On Windows the installer can add per-program firewall
   rules (see [ENTERPRISE.md](ENTERPRISE.md#windows-firewall-rules)).

## Emails, pages and chat exports

`--eml`, `--html` and `--text` (and the GUI's **Open file…**) parse untrusted
documents with the standard library's `email` and `html.parser` modules only.
The guard is installed before parsing starts, the GUI hands the raw bytes to
the isolated worker instead of parsing them itself, and nothing in a document
is fetched, rendered or executed - scripts and comments are only searched for
addresses.

Decoded security-gateway links are trusted only when the wrapper host belongs
to the vendor (for example `*.safelinks.protection.outlook.com`). FortiMail
runs on each organisation's own server, so a `/fmlurlsvc/` link on any other
host is reported as unverified and its wrapper host is checked as well; an
attacker cannot make a phishing link look clean by dressing it up as a
gateway link.

## Privacy

| Data | Where it goes |
| --- | --- |
| Emails, chats and pages you read | Nowhere. The content script reads only the open message, conversation or page, and passes links (with their visible text, at most 500 characters) to the extension. |
| Links checked by the extension (default setting) | The app on this device, over native messaging. Without the app, the extension checks them itself. |
| Threat database, allow/block lists, reported links, settings | Your data folder. Owner-only (`0700`/`0600`) on macOS and Linux; under your profile on Windows. |
| Database updates | `GET` requests for the public lists. The only identifying header is `User-Agent: homograph-guard/<version> (feed updater)`. |
| DNS checks (opt-in in the extension; on by default for links you check by hand in the CLI and GUI) | The host name goes to Google, Cloudflare and AdGuard DNS, from your IP address. |
| Short links (CLI and GUI with DNS checks on; the extension only when you choose "Show where this short link leads") | The short link goes to its shortening service, from your IP address, as a click would. The service, and possibly whoever made the link, can see that it was looked up. The destination is never contacted. |

When DNS checks are on:

- **No network hint.** Every query sends an empty EDNS Client Subnet
  (`0.0.0.0/0`), so a resolver does not pass part of your address on to the
  site's own DNS server, which in phishing is the attacker's. The regional
  comparison uses fixed cloud-provider prefixes instead (Google honours them,
  Cloudflare ignores the option).
- **No read receipts.** For links found in emails and chats, only the registered
  domain is looked up (`example.com`, not `a8f3k2.track.example.com`): a
  sub-domain created for one recipient would otherwise tell the sender that
  the message was opened, and by whom. `--tls-peek` is skipped for such links,
  and short links in them are not expanded unless you ask (a shortening service
  shows its link's creator every lookup; `--expand-in-messages` is meant for
  scanning mail on delivery, when the sender learns nothing new).
- **No cookies or referrer.** The extension's DNS-over-HTTPS requests use
  `credentials: "omit"`, `referrerPolicy: "no-referrer"` and `cache: "no-store"`.
- The resolver operators still see which host names were checked and the IP
  address they came from. If that is not acceptable, keep the extension's DNS
  setting on **Device only** (organisations can lock it).

## Browser extension

- **Device first.** With the app installed, every check goes to the app over
  native messaging and nothing leaves the computer. With the default privacy
  setting the extension makes no network request at all; its content security
  policy allows connections to the five DNS-over-HTTPS resolvers and nothing
  else. It never requests the links themselves.
- **Unlike the CLI**, the extension cannot pin resolver IP addresses: the
  browser resolves `dns.google` and the other resolver names itself.
- **Only what you are looking at** is checked: the open message in Gmail,
  Outlook and Yahoo Mail; roughly the last 24 hours of the open conversation in
  Discord, WhatsApp, Telegram, Slack and Teams; the current page elsewhere.
  Other mails, chats and tabs in the background are not read.
- **Nothing is kept.** No history of pages, links or results is stored. The
  extension's storage holds the on/off switch, the DNS setting and, only when
  the app is not installed, your allow/block lists. It writes nothing to the
  console.
- **Warnings cannot be faked or clicked through by the page.** They are drawn in
  a closed shadow root and in the browser's top layer; attacker-controlled text
  is inserted as text, never as HTML, with bidi and invisible characters shown
  as `<U+XXXX>`. Buttons accept only real clicks (`isTrusted`), only after the
  warning has been fully visible for 700 ms (IntersectionObserver v2 where
  available), which defeats clickjacking and hurried double-clicks.
- **Clicks on risky links are intercepted** before the page sees them. "Open
  anyway" is offered only for `http`, `https` and `mailto` links, never for
  `javascript:` or application handlers. Opening a known-bad site directly
  (typed, or from another program) shows a full-page warning, and so does a
  redirect to one (a short link or tracker that was clicked); that check uses
  only the database on the device and the offline analysis, never DNS.
- **"Show where this short link leads"** (right-click, short links only) runs
  only when you choose it. The app asks the service first; for services that
  answer only browsers, a background tab is opened at `about:blank`, two
  session rules (`declarativeNetRequest`) are added that block every request in
  that tab, and every request the shortening service's pages start elsewhere
  (pop-ups, workers), unless it goes to the shortening service or
  `challenges.cloudflare.com`, and only then is the short link loaded. The first
  request to anywhere else is blocked before it is sent (tested against a real
  server in Chromium, Chrome, Edge and Firefox: the destination never received a
  request) and its address is the answer. The tab is closed and the rules
  removed afterwards, also after a crash or restart. Pop-ups from the tab are
  closed. If the service asks a person to confirm, the tab is shown; the user
  does that, the extension never does. One limit: the browser may still resolve
  or pre-connect to a host the service's page hints at, which is not a request.
- **Messages are checked at every boundary.** The service worker accepts scan
  requests only from its own content scripts and option changes only from its
  own pages; links are size-limited and their context fields allow-listed.
- The site adapters rely on how each web app structures its page. If an app
  changes its markup, the extension falls back to scanning the app's main area
  or the latest messages, and may need an update.

## The browser helper (native messaging)

- Only browsers start it, and only for the extension IDs in its manifest
  (`allowed_origins` / `allowed_extensions`); it also checks the caller origin
  the browser passes to it.
- It has no network listener and no command line input: it reads length-prefixed
  JSON messages (at most 1 MB, 500 links) from the browser and accepts ten
  fixed commands, each with validated arguments. The protocol is fuzzed in the
  tests.
- Its answers contain the analysis and `checked_on: "device"`, never file
  paths, user names, host names or versions of the device (tested).
- It runs as you, under the guard: it may open only the app's own database,
  write only the settings file, and reach the network only if the DNS setting
  allows, and then only the pinned resolvers - or, when you choose "Show where
  this short link leads", the resolvers and that one shortening service (unless
  the `short_links` setting says `browser` or `off`). Links on pages are never
  expanded by themselves.

## The updater

- Downloads only over HTTPS (TLS 1.2 or newer, certificate verified against the
  system store plus an optional corporate CA), only from the feed hosts or an
  organisation mirror, following redirects only to allowed hosts, at most
  64 MB per feed.
- Fails closed: a proxy that intercepts TLS without a trusted CA, an oversized
  or empty feed, or a feed that shrinks below a fifth of its last size leaves
  the previous data in place.
- Survives interruptions: every feed is replaced in one SQLite transaction (WAL,
  `synchronous=FULL`), so a power cut or a killed process leaves each feed fully
  old or fully new, and the next run fetches only what is missing. The updater
  checks every page of the database first (`PRAGMA quick_check`); a damaged file
  is set aside, not deleted, and rebuilt with the user's lists, which are also
  kept in `lists-backup.json` (written atomically, owner-only on macOS and Linux).
- Feed entries cannot be used to block the internet's foundations: public
  suffixes, shared platforms (`github.io`, `blogspot.com`), shared
  infrastructure (`googleapis.com`, `cloudfront.net`), company-owned TLDs and
  the protected brands are refused as whole-domain entries.
- Runs as the signed-in user (Task Scheduler with least privilege, a systemd
  user service with `NoNewPrivileges` and a system-call filter, or a launchd
  agent), under the guard, which lets it resolve and reach only the feed hosts
  or the configured proxy.

## Known limits

- A DNS-only check cannot see page content. A clean result means "no
  homograph, database or DNS indicators", not "safe".
- Filtering resolvers block different things. AdGuard's default server also
  blocks ad and tracker domains, so an AdGuard block is a strong hint rather
  than proof of phishing.
- CDNs and GeoDNS legitimately return different addresses to different
  resolvers; the tool compares subnets, announced prefixes and networks (ASNs),
  not just IPs, for that reason.
- If TLS to the resolvers is intercepted (corporate proxy, antivirus web
  shield), answers may be altered. The tool reports the certificate issuer
  and warns when it is not a public CA.
- `--tls-peek` reveals your IP address to the server operator.
- Any program running as you can also start the browser helper or edit your
  data folder; the operating system's user separation is the boundary.
- Some click-protection services (Mimecast, SendGrid, Mailchimp) do not reveal
  the destination in the link at all; only the wrapper can be checked.
- Links inside images (QR codes) and inside attachments other than HTML/SVG are
  not read.
- A shortening service decides where its link leads each time it is asked; it
  can show one destination to the check and another to a later click. Clicked
  links are still checked when they redirect (the extension's redirect guard).

## Reporting a vulnerability

Please use GitHub's private **Report a vulnerability** form on this
repository rather than opening a public issue.
