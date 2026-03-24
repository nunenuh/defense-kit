# Defense: Webshells

## Threat

Attackers upload webshells (PHP, Python, JSP) to web servers for persistent remote access. The webshell looks like a normal web page but executes system commands.

## Detection

### defense-kit scanners
- `credentials` — may find hardcoded webshell passwords
- `processes` — detects web server spawning shell processes
- `file_integrity` — detects new files in web directories

### Manual verification
```bash
# Find recently modified files in web directories
find /var/www -name "*.php" -mtime -7 2>/dev/null
find /var/www -name "*.jsp" -mtime -7 2>/dev/null

# Find suspicious PHP functions
grep -rn "eval\|base64_decode\|system\|exec\|passthru\|shell_exec" /var/www/ --include="*.php" 2>/dev/null

# Find encoded/obfuscated files
grep -rn "chr(\|\\\\x[0-9a-f]" /var/www/ --include="*.php" 2>/dev/null

# Check for web server spawning shells
ps aux | grep -E "www-data.*(/bin/sh|/bin/bash|python|perl)"

# Check access logs for webshell access
grep -E "cmd=|exec=|shell=|c=whoami" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null
```

## Response

1. **Identify**: find the webshell file(s)
2. **Capture**: copy for analysis before removing
3. **Remove**: delete the webshell
4. **Patch**: fix the vulnerability that allowed upload
5. **Audit logs**: check access logs for webshell usage (what commands ran)
6. **Check for persistence**: webshells often install secondary backdoors

## Prevention

```bash
# Restrict web directory write permissions
chown -R root:www-data /var/www
chmod -R 755 /var/www
find /var/www -type f -exec chmod 644 {} \;

# Disable dangerous PHP functions
echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen" >> /etc/php/*/fpm/php.ini

# File integrity monitoring
aide --init && aide --check

# Monitor file creation in web dirs with auditd
auditctl -w /var/www -p wa -k webshell_watch
```

## References
- [Linux Persistence: Webshells - pberba](https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/)
