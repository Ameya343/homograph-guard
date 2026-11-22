# Debian with systemd as PID 1, to run the per-user daily update timer for real.
FROM python:3.15-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus dbus-user-session libpam-systemd ca-certificates >/dev/null \
    && rm -rf /var/lib/apt/lists/* && useradd -m -s /bin/bash tester
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
