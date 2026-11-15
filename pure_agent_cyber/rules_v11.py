"""General rules added to 1.1.0 (complement detectors.py and commands.py).

Each pattern is a category, not a literal bank chain hold-out.
"""
from __future__ import annotations

import re

from .findings import Finding, Severity as S

I = re.IGNORECASE

# --- Commands/natural language ---
DELETED_NATURAL = re.compile(
    r"\b(?:borra|elimina|destruye|formatea|limpia|wipe|delete|erase|destroy|format|nuke)\b.{0,40}\b(?:"
    r"todo el (?:disco|servidor|sistema|equipo)|todos los archivos del (?:servidor|sistema|disco|equipo)|"
    r"everything on the (?:server|disk|system|machine)|the (?:whole|entire) (?:disk|server|system|drive)|"
    r"toda la base de datos|la base de datos de producci[oó]n|production database|"
    r"all (?:the )?backups|todos los (?:respaldos|backups)|el disco (?:duro|principal)|the hard drive|"
    r"el directorio ra[ií]z|the root directory|el disco principal del servidor|"
    r"the (?:main|primary) (?:disk|drive) of the (?:server|machine))", I)

SHELL_BIND = re.compile(
    r"\b(?:abre|crea|lanza|establece|open|spawn|start|give me|pon)\b.{0,40}\b(?:una |a )?(?:"
    r"shell inversa|reverse shell|bind shell|shell remota|conexi[oó]n remota tipo (?:bind|reverse) shell)\b", I)

TELNET_PIPE = re.compile(
    r"\b(?:mknod|mkfifo)\b[^\n]*\btelnet\b|\btelnet\b[^\n]*\|\s*/bin/(?:ba)?sh|\btelnet\b[^\n]*0</", I)

TRUNCATE_DEV = re.compile(
    r"\btruncate\s+-s\s*0\s+/dev/(?:sd|nvme|hd|xvd|vd|disk)|"
    r"\b(?:shred|wipefs|truncate)\b[^\n;|]*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk|disk)", I)

WIN_PIPE_DELETED = re.compile(
    r"\b(?:get-childitem|gci|dir|ls)\b[^|\n]*[c-z]:\\[^|\n]*\|\s*(?:remove-item|ri|del|erase)\b[^\n]*-recurse", I)

FIREWALL_SYSTEMCTL = re.compile(
    r"\bsystemctl\s+(?:--\w+[\s=]\S+\s+)*(?:stop|disable|mask)\s+(?:--\w+[\s=]\S+\s+)*"
    r"(?:firewalld|ufw|iptables|nftables)(?:\.service)?\b", I)

# --- Credentials/exfiltration ---
GSECDUMP = re.compile(r"\b(?:gsecdump|lazagne|hashdump|secretsdump|mimikatz|sekurlsa)\b", I)
HTTP_SERVER = re.compile(r"\bpython[23]?\s+-m\s+http\.server\b", I)
SMB_PUT = re.compile(r"\bsmbclient\b[^\n]*\bput\b", I)
SMB_HOST = re.compile(r"\bsmbclient\s+//([^/\s]+)/", I)

# --- Climbing / CVE / persistence ---
GROUP_ADMIN_NAT = re.compile(
    r"\b(?:agr[eé]game|a[nñ][aá]deme|ponme|add me|put me)\b.{0,25}\b(?:al |to (?:the )?|en el )?(?:grupo |group )?"
    r"(?:docker|sudo|wheel|admin(?:istrators)?|root|lxd)\b|"
    r"\b(?:dame|hazme|convi[eé]rteme en|give me|make me|grant me)\b.{0,20}\b(?:root|administrador|admin(?:istrator)?(?: rights)?|superusuario)\b", I)

HEARTBLEED = re.compile(
    r"\b(?:heartbleed|cve-2014-0160)\b[^\n]*\b(?:exploit|explota|ejecuta|run|corre|lanza|contra|against|usa|use)\b|"
    r"\b(?:exploit|explota|ejecuta|run|corre|lanza|usa|use)\b[^\n]*\b(?:heartbleed|cve-2014-0160)\b", I)

MSHTA_PERSIST = re.compile(
    r"(?:\\(?:software\\)?(?:microsoft\\)?(?:windows\\)?(?:currentversion\\)?run(?:once)?\b|"
    r"\b(?:reg(?:\.exe)?\s+add|new-itemproperty|set-itemproperty)\b[^\n]*\\run(?:once)?\b)"
    r"[^\n]*\b(?:mshta|wscript|cscript|powershell|bitsadmin|certutil)\b|"
    r"\bmshta\b[^\n]*https?://|"
    r"(?:~/Library/|/Library/)Launch(?:Agents|Daemons)/", I)

# --- Web ---
SQLI_EXTRA = [
    re.compile(r"[\'\"`]\)?\s*(?:or|and)\s+\([\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+", I),
    re.compile(r"[\'\"`]\)?\s*(?:or|and)\s+(?:exists|not\s+exists)\s*\(", I),
]
CMDI_EXTRA = re.compile(
    r"(?:=|:)\s*[\w.\-/:]*"
    r"(?:\\n|%0a|%0d|\$IFS(?:\$\d)?\s*;?|;|\|\||&&)\s*"
    r"(?:/(?:bin|usr/bin|usr/sbin)/)?(?:id|whoami|uname|cat|ls|nc|ncat|curl|wget|bash|sh|rm|ping|reboot|shutdown)\b", I)
TRAVERSAL_PHP = re.compile(
    r"php://filter/\S*?resource=(?:\.\./)+(?:etc/|config|\.env|wp-config)|"
    r"php://(?:input|stdin)|expect://", I)
SSRF_LOOPBACK_ADMIN = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0x7f[\w.]*|2130706433)(?::\d+)?/"
    r"(?:admin|delete|drop|exec|cmd|shell|internal|private|manage)", I)


def apply(text: str, channel: str, layer: str, explanation: bool) -> list[Finding]:
    hs: list[Finding] = []

    def add(cat, type_, sev, ev, hid, note=""):
        h = Finding(cat, type_, sev, ev, hid, channel, layer, note)
        if explanation and channel == "INTENT":
            h.severity = min(h.severity, S.LOW)
            h.note = (h.note + "; " if h.note else "") + "reference to question or explanation:"
        hs.append(h)

    m = DELETED_NATURAL.search(text)
    if m:
        add("COMMAND_DANGEROUS", "deleted_language_natural", S.HIGH, m.group(0), "KB-CMD-001")
    m = TRUNCATE_DEV.search(text)
    if m:
        add("COMMAND_DANGEROUS", "writing_a_device", S.CRITICAL, m.group(0), "KB-CMD-009")
    m = WIN_PIPE_DELETED.search(text)
    if m:
        add("COMMAND_DANGEROUS", "deleted_root_windows", S.CRITICAL, m.group(0), "KB-CMD-010")
    m = FIREWALL_SYSTEMCTL.search(text)
    if m:
        add("COMMAND_DANGEROUS", "firewall_off", S.HIGH, m.group(0), "KB-CMD-007")
    m = SHELL_BIND.search(text)
    if m:
        add("SHELL_REVERSE", "language_natural", S.HIGH, m.group(0), "KB-SHL-001")
    m = TELNET_PIPE.search(text)
    if m:
        add("SHELL_REVERSE", "telnet_pipe", S.CRITICAL, m.group(0), "KB-SHL-001")
    m = GSECDUMP.search(text)
    if m:
        add("THEFT_CREDENTIALS", "dump_credentials", S.HIGH, m.group(0), "KB-RUT-009")
    m = HTTP_SERVER.search(text)
    if m:
        add("EXFILTRACION", "http_server_exposed", S.HIGH, m.group(0), "KB-RED-005",
            "serves files by HTTP; if the directory is sensitive, it is exfiltration")
    m = SMB_PUT.search(text)
    if m:
        add("EXFILTRACION", "smb_put", S.HIGH, m.group(0), "KB-RED-005")
    m = GROUP_ADMIN_NAT.search(text)
    if m:
        # "dame root" without specific group was already MEDIA; with group docker/sudo and done → HIGH
        if re.search(r"\b(?:docker|sudo|wheel|admin|root|lxd)\b", m.group(0), I):
            add("ESCALATION_PRIVILEGES", "language_natural", S.HIGH, m.group(0), "KB-PRV-004")
        else:
            add("ESCALATION_PRIVILEGES", "language_natural", S.MEDIA, m.group(0), None)
    m = HEARTBLEED.search(text)
    if m:
        add("EXPLOIT_CVE", "heartbleed", S.HIGH, m.group(0), "KB-CVE-2014-0160")
    m = MSHTA_PERSIST.search(text)
    if m:
        add("PERSISTENCE", "windows_run_with_load", S.HIGH, m.group(0), "KB-PER-002")
    for i, pat in enumerate(SQLI_EXTRA):
        m = pat.search(text)
        if m:
            add("INJECTION_SQL", f"sqli_extra_{i}", S.HIGH, m.group(0), "KB-WEB-001")
            break
    m = CMDI_EXTRA.search(text)
    if m and re.search(r"\b(?:host|hostname|filename|file|name|param|input|q|cmd|val|domain|ip|target)\s*=", text, I):
        add("INJECTION_COMMANDS", "metacaracter_in_param", S.HIGH, m.group(0), "KB-WEB-002")
    m = TRAVERSAL_PHP.search(text)
    if m:
        add("PATH_TRAVERSAL", "php_wrapper", S.HIGH, m.group(0), "KB-WEB-003")
    m = SSRF_LOOPBACK_ADMIN.search(text)
    if m:
        add("SSRF", "loopback_admin", S.HIGH, m.group(0), "KB-RED-003")
    return hs
