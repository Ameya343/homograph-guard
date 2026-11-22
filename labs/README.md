# Labs

Repeatable checks in Docker, beyond the unit tests. Each script cleans up after itself.
They run from Linux, macOS or Windows (Git Bash) with Docker.

| Lab | What it shows | Run |
| --- | --- | --- |
| `linux/` | In a clean Debian container (Python 3.15), as a normal user: the whole test suite; the extension in Chromium with and without the app on the device; registration with Chrome, Edge, Brave, Chromium and Firefox, per user and machine-wide; the daily schedule (cron fallback). | `bash labs/linux/run.sh` |
| `systemd/` | The per-user daily update timer under a real systemd: created by `setup schedule install`, the update service run once with its sandbox settings (`NoNewPrivileges`, system-call filter, `UMask=0077`), owner-only data files, a second run skipped, then removed. Needs a privileged container for systemd. | `bash labs/systemd/run.sh` |
| `enterprise/` | A corporate network with no direct internet and a TLS-inspecting proxy (mitmproxy) as the only way out; the employee machine is the hardened image. Checks: updates refused without the company's root certificate and working with it (from the policy file), locked settings, organisation allow and block lists, DNS checks degrading quickly when DNS-over-HTTPS is blocked, an air-gapped update from an internal mirror, and a list of every request that crossed the proxy. | `bash labs/enterprise/run.sh [python]` |

The enterprise lab needs a local Python with the `cryptography` package to make
its throwaway CA. Generated certificates and logs stay in the lab folder and are
ignored by git.
