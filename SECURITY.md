# Security Policy

Mapache runs with administrator rights, deletes files and changes system settings, so security issues
are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security** tab → **Report a vulnerability**.

Include what you found, the steps to reproduce it, the affected version and the impact you expect.
You will get an acknowledgment within 7 days. Once a fix is released, the report can be published and
credited to you if you wish.

## Scope

Examples of what counts as a vulnerability:

- Privilege escalation through an elevated Mapache process (for example, data from a user-writable
  location such as HKCU being executed or trusted with admin rights).
- Command or PowerShell injection through file names, registry values or other system data.
- Deleting or modifying something outside what the user selected and confirmed.
- An undo that does not restore the previous state, or backups that are not taken.
- Any path that disables Microsoft Defender or other security software.

A setting that is a deliberate trade-off and is documented as such (for example, what a hardening rule
may break) is not a vulnerability, but feedback on it is welcome as a regular issue.

## Supported versions

Only the latest release receives security fixes.
