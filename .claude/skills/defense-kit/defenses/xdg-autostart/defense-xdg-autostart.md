# Defense: XDG Autostart Persistence

## Threat

Malware creates `.desktop` files in XDG autostart directories to execute when a user logs into a GUI session. Least monitored persistence mechanism on Linux desktops — cron and systemd get attention, XDG autostart does not.

**MITRE ATT&CK:** T1547.013

## Why It's Dangerous

- Executes in user's GUI session (access to display, clipboard, keystrokes)
- No root required — user-level persistence
- Most security tools don't monitor `~/.config/autostart/`
- Looks legitimate — `.desktop` files are standard Linux format
- Can enable keylogging, screen capture, clipboard hijacking

## Detection

### defense-kit scanners
- `shell_rc` — partially covers this (checks RC files, not .desktop)
- `clipboard` — detects keyloggers that may be started via XDG

### Manual verification
```bash
# Check system-wide autostart
ls -la /etc/xdg/autostart/

# Check per-user autostart
for user in /home/*/; do
    echo "=== $user ==="
    ls -la "${user}.config/autostart/" 2>/dev/null
done

# Verify each Exec directive against packages
for f in /etc/xdg/autostart/*.desktop ~/.config/autostart/*.desktop; do
    [ -f "$f" ] || continue
    exec_cmd=$(grep "^Exec=" "$f" | head -1 | cut -d= -f2-)
    binary=$(echo "$exec_cmd" | awk '{print $1}')
    pkg=$(dpkg -S "$binary" 2>/dev/null)
    echo "$f → $binary → ${pkg:-NOT FROM PACKAGE}"
done

# Find recently created .desktop files
find /etc/xdg/autostart ~/.config/autostart -name "*.desktop" -mtime -7 2>/dev/null
```

## Response

1. **Review**: check Exec= line in suspicious .desktop file
2. **Remove**: delete the .desktop file
3. **Kill**: stop the running process it launched
4. **Audit**: check when the file was created and by whom

## Prevention

```bash
# Restrict system autostart to root
chmod 755 /etc/xdg/autostart
chown root:root /etc/xdg/autostart

# Monitor with auditd
auditctl -w /etc/xdg/autostart -p wa -k xdg_autostart
auditctl -w /home -p wa -k user_autostart

# Inventory autostart entries periodically
defense-kit schedule enable --interval 6h
```

## References
- [XDG Autostart T1547.013 - MITRE ATT&CK](https://www.startupdefense.io/mitre-attack-techniques/t1547-013-xdg-autostart-entries)
