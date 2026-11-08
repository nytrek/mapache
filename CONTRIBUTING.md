# Contributing to Mapache

Thanks for your interest. This document describes how the code is organized and how to extend it.

## Ground rules

- **Standard library only.** No third-party packages.
- **Every visible string goes through `t("key")`** and lives in both `mapache/locales/en.json` and
  `mapache/locales/es.json`. The tests check that both files have the same keys and placeholders.
- **Nothing is deleted or changed without an explicit selection and confirmation**, and everything must
  honor `--simulate` (`log.dry`).
- **Settings must be reversible.** Every action reads the current state, applies, and can revert to the
  exact previous value.
- **Never disable Microsoft Defender**, and never offer to disable security software.
- **Never interpolate variable data into PowerShell.** Pass it through `$env:MAPACHE_*` variables.
- Comments in English, short, explaining *why* rather than *what*.
- Test destructive features with `python -m mapache --simulate` before running them for real.

Run the tests before opening a pull request:

```
python tests/test_core.py
```

They run on any OS and use temporary folders only.

## Layout

```
mapache/
  app.py              arguments, elevation and main menu
  i18n.py             t(), language detection
  config.py           %APPDATA%\Mapache\config.json
  locales/            en.json, es.json
  core/
    paths.py          system paths and constants
    fs.py             long paths, sizes, dry-run aware deletion
    scan.py           DriveScan: one multithreaded scan of the drive, shared by every module
    ctx.py            Ctx: admin flag, dry run, shared scan, path claims
    model.py          Item (something the user can select) and BigFile
    log.py            screen + file log
    proc.py           run_cmd, powershell(), process helpers
    winreg_util.py    read-only registry helpers
    backup.py         reg export / task export before deletion
    uninstaller.py    installer type detection and official uninstall
    lnk.py            .lnk target parser (MS-SHLLINK)
    elevate.py        UAC relaunch
  ui/
    console.py        colors and formatting
    selector.py       checkbox list and menu (arrow keys, search, sort; numbered fallback)
  modules/
    diskreport.py     disk report
    cleaner/          one detector per file
    programs/         inventory, last use, leftovers
    audit/            facts.py (data), checks/ (one function per check), report.py
    harden/           engine.py (actions), rules.py (rules as data), __init__.py (Suite: apply/undo/guides)
    privacy/          rules.py on the hardening engine
    optimize/         actions.py and rules.py (fixed + dynamic rules) on the hardening engine
tests/
  test_core.py
```

## Core concepts

**Shared scan.** `ctx.ensure_scan()` walks the system drive once. Modules ask for sizes with
`ctx.size(path)` instead of walking the disk again. Call `ctx.invalidate()` after deleting files.

**Claims.** Cleaner detectors run in order. A detector calls `ctx.claim(path)` for what it offers so the
next ones do not offer the same files again.

**Items.** Everything the user selects is an `Item`: group, title, size, level (`rec` is preselected,
`opt` is not), note, an `action(log)` callable, whether it needs admin, and an execution order.

**Dry run.** `Log.dry` is true under `--simulate`. `run_cmd`, deletion helpers and every action check
it and only print what they would do.

## Adding a cleaner detector

1. Create `mapache/modules/cleaner/<name>.py` with `detect(ctx) -> list[Item]`.
2. Add it to `DETECTORS` in `mapache/modules/cleaner/__init__.py`. Order matters because of claims.
3. Add its texts to both locale files.

Detectors that use the whole-drive scan must restrict themselves to user folders and skip program and
tool folders (`fs.in_tool_dir`).

## Adding an audit check

Checks live in `mapache/modules/audit/checks/<category>.py`:

```python
@check("my_check", "system", 2, refs=("ATT&CK T1234",), harden="sys.my_setting")
def my_check(f):
    if f.val(r"SOFTWARE\Policies\...", "Value") == 1:
        return R("pass", t("audit.on"))
    return R("warn", t("audit.off"))
```

- `f` is a `Facts` object. Read the registry with `f.val()` / `f.values()` and PowerShell data with
  `f.psv(section)`. New PowerShell data goes into `PS_BUNDLE` in `facts.py`, inside its own try/catch.
- Statuses: `pass`, `warn` (half credit), `fail`, `info` and `unknown` (not scored).
- `harden` links the check to the setting that fixes it.
- Texts: `audit.<id>.title`, `audit.<id>.why`, `audit.<id>.fix`.
- Tests build `Facts(admin=..., reg={...}, ps={...})` with fake data; add one for the new check.

## Adding a setting (Hardening, Privacy, Optimization)

Settings are data. Add a `Rule` to the module's `rules.py`:

```python
Rule("sys.my_setting", "basic", "low", lambda: [
    RegValue("HKLM", r"SOFTWARE\Policies\...", "Value", "REG_DWORD", 1)],
    refs=("MS: ...",)),
```

- Levels: `basic` (preselected, clearly safe), `advanced`, `paranoid`. Risk: `low`, `medium`, `high`.
- Texts: `<module>.<id>.title`, `.desc` and `.breaks` (what it may break).
- Available actions in `harden/engine.py`: `RegValue` (with `default` for missing values and `accept`
  for equivalent values), `MpPref`, `AsrRule`, `Feature`, `FirewallOn`, `HibernateOff`; and in
  `optimize/actions.py`: `StartupOff`, `TaskOff`, `PowerPlan`.
- A new action type implements `read`, `is_applied`, `apply`, `revert` and `params`, and is registered in
  `engine.KINDS` so Undo can rebuild it from the snapshot.
- Browser policies must be checked against the vendor's policy list and then in `chrome://policy`
  (or `edge://policy`, `brave://policy`).

The shared flow in `harden/__init__.py` (`Suite`) handles selection, restore point, the JSON snapshot
(saved after every change) and Undo.

## Adding a language

Copy `mapache/locales/en.json` to `<code>.json`, translate the values (keep the `{placeholders}`), and add
the language to `LANGS` in `mapache/i18n.py`.
