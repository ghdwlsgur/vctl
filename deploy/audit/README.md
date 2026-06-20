# Host-side kernel audit (session-stamped)

Captures *what was done* inside an SSH session at the kernel level and ships it
to vctl's central store, attributed to a human (not just the shared login user).
Two uses: **audit** ("who ran what, where, when") and **dataset** (structured SRE
work per host, exported via `vctl session --json` for an agent).

> Status: the Go side (schema, `vctl session` / `vctl collect` / `vctl session-start`)
> is tested against the central DB. The host wiring below is a reference
> deployment — validate on a canary host before fleet/golden-image rollout.

## Pieces

```
ssh login ──▶ sshd (ExposeAuthInfo) ──▶ $SSH_USER_AUTH file (cert offered)
                     │
            PAM session-open hook (pam-session-stamp.sh)
                     │  extracts cert serial, writes a marker file
                     ▼
           /run/vctl/sessions/<pid>.json   (serial, login, rhost, leader pid)

Tetragon (eBPF) ──exec/exit/open/connect──▶ JSON stream
                     │
        vctl-collect.service:  tetra getevents -o json | vctl collect
                     │  (privileged: holds Vault AppRole creds)
                     ▼
        central Postgres: audit_session + kernel_event
                     ▲
        the same daemon reads markers and calls `vctl session-start`
        so events attribute to the human via cert serial / cgroup.
```

**Why a marker + daemon (not vctl at login):** the login user (ubuntu/root) has
no Vault creds, and you don't want creds on every login. The PAM hook only drops
a local marker; one privileged daemon (AppRole) does all central writes.

## Install (per host, or bake into the golden image)

1. **sshd** — expose the offered cert to the session:
   - drop `sshd/10-expose-authinfo.conf` into `/etc/ssh/sshd_config.d/`, reload sshd.
2. **PAM stamp** — `pam-session-stamp.sh` → `/usr/local/sbin/`, and add to
   `/etc/pam.d/sshd`:
   ```
   session optional pam_exec.so /usr/local/sbin/pam-session-stamp.sh
   ```
3. **Tetragon** — install (DaemonSet on k8s nodes, or systemd on bare VMs) with
   `tracingpolicy-ssh.yaml`.
4. **Collector + session registrar** — install `vctl-collect.service` (Tetragon
   → events) and `vctl-watch-sessions.service` (PAM markers → sessions), with
   AppRole creds in `/etc/vctl/` (role → `vctl-rw`), enable both.
5. **Log rotation** — both daemons log to journald; install
   `journald-vctl-audit.conf` → `/etc/systemd/journald.conf.d/` to cap journal
   growth, and `logrotate-vctl-audit.conf` → `/etc/logrotate.d/` for any
   file-based logs (Tetragon export buffer, etc.). Kernel events live in central
   Postgres and are pruned by `vctl prune` (CronJob) — host logs are bounded
   separately so a busy host can't fill its disk.

For OpenStack VMs: bake steps 1–4 into the golden image. New VMs then audit
themselves with zero per-host onboarding — same pattern as the SSH CA trust
(only the CA public key / AppRole role-id are baked; secret-id delivered at boot).

## Notes / TODO
- `vctl collect` currently ingests `process_exec` / `process_exit`. File
  (`open`) and network (`connect`) events arrive via Tetragon kprobe policies;
  extend `mapTetra` to map them.
- Session linking uses cgroup id when present, else cert serial. Populating
  `cgroup_id` from Tetragon (and into the marker) makes linking exact under
  concurrent sessions from the same user.
- The marker→session loop is `vctl watch-sessions` (vctl-watch-sessions.service);
  it derives the cgroup id from `/proc/<pid>/cgroup` so Tetragon events link by
  cgroup, falling back to cert serial.
