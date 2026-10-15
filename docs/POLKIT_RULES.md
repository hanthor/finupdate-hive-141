# Polkit Authorization Rules for Finupdate

## Overview

Finupdate needs root privileges for bootc operations and for system management. This document describes the Polkit rules that allow these operations with no password prompt. The rules apply to tests and to routine use.

## Rule: `/etc/polkit-1/rules.d/49-finupdate.rules`

### Purpose
Allows members of the `wheel` group to run the allowlisted bootc and
finupdate-runner programs with no password prompt. Members can also reboot the
system. Designed for:
- Automated tests in CI/CD environments
- Development/debug mode operations
- Non-destructive command verification (bootc status, upgrade checks)

### Configuration
```javascript
// The exec allowlist matches the FULL program path, exactly.
var FINUPDATE_ALLOWED_PROGRAMS = [
    "/usr/bin/bootc",
    "/usr/sbin/bootc",
    "/usr/bin/finupdate-runner",
    "/usr/libexec/finupdate-runner"
];

polkit.addRule(function(action, subject) {
    if (subject.isInGroup("wheel")) {
        if (action.id == "org.freedesktop.policykit.exec") {
            var program = action.lookup("program");
            if (program && FINUPDATE_ALLOWED_PROGRAMS.indexOf(program) >= 0) {
                return polkit.Result.YES;
            }
        }
        // Allow systemctl reboot for integration testing
        if (action.id == "org.freedesktop.login1.reboot") {
            return polkit.Result.YES;
        }
    }
});
```

The full shipped rule is `build-aux/49-finupdate.polkit.rules`; keep the two
in step.

**Match the whole path, never a part of it.** `program.indexOf("bootc") >= 0`
authorizes every executable whose path *contains* that text. Thus any
unprivileged process can put a script at `/home/u/bootc/x.sh` or
`/tmp/finupdate-runner-1234.sh`, and root runs it with no password. A
path belongs on the allowlist only if root owns it. Also, no unprivileged user
can write to it or to any directory above it.

### Operations Authorized

#### bootc commands (all variants)
- `bootc status --json` — Query the metadata of the current OS image
- `bootc status` — Human-readable status output
- `bootc upgrade` — Stage image upgrades
- `bootc upgrade --check` — Check for available upgrades

Executed via:
- Direct: `pkexec bootc <command>`
- From Flatpak: `flatpak-spawn --host pkexec bootc <command>`

#### System reboot
- `systemctl reboot` — Start a system restart
- Polkit action: `org.freedesktop.login1.reboot`

#### Systemd unit management
The rule does not grant `org.freedesktop.systemd1.manage-units` or
`org.freedesktop.systemd1.manage-unit-files`. Finupdate turns the `uupd`
timer on or off with `pkexec systemctl enable|disable --now uupd.timer`.
`systemctl` then runs as root, so systemd does not ask polkit about the unit.
`pkexec` asks for the admin password, because `systemctl` is not on the
allowlist.

Do not add a grant for these two actions. A grant for the `wheel` group gives
each session control of all units and unit files with no password. That is
root code execution. The `manage-unit-files` action has no unit detail, so a
rule cannot limit it to one unit.

### Security Notes

**Scope**: Limited to members of `wheel`, and — for `pkexec` — to the exact
program paths on the allowlist. It does not authorize arbitrary commands as root
*provided* the allowlist stays exact-match and every entry is
root-owned. A partial match, or an entry under a user-writable directory,
removes that guarantee entirely.

**Assumptions**: This configuration assumes that you trust members of `wheel`
with system administration. Note what it still changes even so: `sudo`
normally re-authenticates, and this rule does not. Think of a machine where the
administrator's `sudo` needs a password. With this rule, code
that runs in that user's session can get to
the allowlisted programs as root with no prompt at all. That code can be a compromised app, not a person.

**Non-destructive intent**: The rule authorizes operations that are necessary to check and manage updates, not arbitrary system changes. The finupdate app has more safeguards:
- Dev mode prevents actual reboots
- Simulation scenarios let you test safely, with no change to the real system

### Installation

Install the rule during system setup or when you initialize finupdate:

```bash
sudo install -m 0644 build-aux/49-finupdate.polkit.rules \
    /etc/polkit-1/rules.d/49-finupdate.rules
```

Install the file from the repository. Do not paste a second copy of
the rule. Then there is only one reviewed version of the allowlist.

### Verification

Test that rules are in effect:

```bash
# Should complete without password prompt
flatpak-spawn --host pkexec bootc status --json

# Should show current deployment info
pkexec bootc status
```

### Upstream Proposal

We intend this rule as a model to send upstream into the Dakota OS layer or a finupdate system package. The specific actions (bootc status, reboot) are legitimate for any system update tool. Other projects can make them general for broader use.

## Related Issues

- **AT-SPI test dependencies**: See `docs/GUI_TESTING.md` for notes on `gnome-ponytail-daemon` requirement for automated GUI tests.

## References

- [Polkit Documentation](https://www.freedesktop.org/software/polkit/docs/latest/)
- [systemd-logind D-Bus Interface](https://dbus.freedesktop.org/doc/org.freedesktop.login1.html)
- [bootc Documentation](https://containers.github.io/bootc/)
