"""Specialty Interpreter: only proposes close list commands.

It does not execute, does not sign tokens, does not read the key HMAC. It recognizes a finite set of legitimate security and administration tasks (reading own logs, scanning, consulting status, updating, blocking a IP...). If it does not recognize the task, it does not propose anything, and the agent responds UNDETERMINED: it does not allow what is not understood.
"""
from __future__ import annotations

import re
import shlex

from .actions import CyberAction as A
from .detectors import (EXPLANATION, SEND_NATURAL, _classify_host, _domain_trusted,
                         destinations_in, urls_in)

# Commands of reading, diagnosis, defense or maintenance that the interpreter recognizes.
# Being here doesn't authorize them: they still go through the detectors, and then through the token.
COMMANDS_RECOGNIZED = {
    "ls", "cat", "grep", "egrep", "zgrep", "fgrep", "rg", "tail", "head", "less", "more", "wc", "sort", "uniq", "cut",
    "awk", "sed", "tr", "jq", "journalctl", "systemctl", "service", "ps", "top", "htop", "pgrep", "df", "du", "free",
    "uptime", "uname", "hostname", "whoami", "id", "w", "who", "last", "lastb", "lastlog", "ss", "netstat", "lsof", "ip",
    "ifconfig", "ping", "traceroute", "tracepath", "mtr", "dig", "nslookup", "host", "whois", "curl", "wget", "openssl",
    "sha256sum", "sha1sum", "md5sum", "gpg", "apt", "apt-get", "dnf", "yum", "pip", "pip3", "pip-audit", "npm", "yarn",
    "git", "docker", "kubectl", "helm", "crontab", "ufw", "iptables", "nft", "fail2ban-client", "auditctl", "ausearch",
    "aureport", "aide", "clamscan", "freshclam", "rkhunter", "chkrootkit", "lynis", "trivy", "grype", "syft", "semgrep",
    "bandit", "gitleaks", "trufflehog", "nmap", "tcpdump", "tshark", "find", "chmod", "chown", "tar", "gzip", "gunzip",
    "zip", "unzip", "cp", "mv", "mkdir", "touch", "ssh", "ssh-keygen", "ssh-copy-id", "scp", "logrotate", "certbot",
    "python", "python3", "pytest", "make", "echo", "date", "stat", "file", "getfacl", "sestatus", "aa-status", "getenforce",
    "osqueryi", "yara", "suricata", "zeek", "wazuh-control", "vmstat", "iostat", "dmesg", "lsblk", "blkid", "mount",
    "timedatectl", "hostnamectl", "loginctl", "passwd", "chage", "faillock", "pam_tally2", "visudo", "sudo", "nginx",
    "apachectl", "testssl.sh", "sslscan", "nikto", "zap-baseline.py", "brew", "snap", "flatpak", "terraform", "aws",
    "gcloud", "az", "psql", "mysql", "sqlite3", "redis-cli", "watch", "diff", "cmp", "basename", "dirname", "realpath",
    "readlink", "xargs", "tee", "printf", "nc", "base64", "test", "true", "history", "type", "which", "whereis", "man",
    "lsattr", "chattr", "setfacl", "umask", "groups", "getent", "dpkg", "rpm", "needrestart", "unattended-upgrade",
    "unattended-upgrades", "Get-EventLog", "Get-WinEvent", "Get-Process", "Get-Service", "Get-NetTCPConnection",
    "Get-MpComputerStatus", "Start-MpScan", "Update-MpSignature", "Get-LocalUser", "Get-FileHash", "netsh", "rm", "for", "while",
    "do", "done", "useradd", "usermod", "gpasswd", "userdel", "groupadd", "mysqldump", "pg_dump", "rsync", "sftp", "kill", "pkill",
}

INTENT_DEFENSIVE = re.compile(
    r"\b(?:revisa|analiza|lee|l[eé]eme|muestra|mu[eé]strame|lista|enlista|verifica|comprueba|checa|chequea|consulta|resume|res[uú]meme|explica|"
    r"genera|crea un reporte|haz un reporte|cuenta|busca|encuentra|monitorea|vigila|actualiza|parchea|aplica|instala|rota|renueva|configura|habilita|"
    r"activa|respalda|cifra|endurece|audita|escanea|investiga|correlaciona|compara|calcula|valida|documenta|prepara|redacta|dime|ens[eé][nñ]ame|"
    r"review|analy[sz]e|read|show|list|check|verify|summari[sz]e|explain|generate|create a report|count|search|find|monitor|update|patch|apply|"
    r"install|rotate|renew|configure|enable|backup|back up|encrypt|harden|audit|scan|investigate|correlate|compare|calculate|validate|document|"
    r"prepare|draft|tell me|teach me|help me|ay[uú]dame|bloquea|block|revoca|revoke|pon en cuarentena|quarantine|alerta|alert|notifica|notify|"
    r"reporta|report|inspecciona|inspect|identifica|identify|detecta|detect|mide|measure|eval[uú]a|evaluate|reinicia|restart|recarga|reload|"
    r"agrega|a[nñ]ade|add|programa|schedule|cambia|change|desactiva la cuenta|disable the account|"
    r"traduce|translate|clasifica|classify|prioriza|prioritize|escribe|write|crea|create|descarga|download|consulta|query|"
    r"copia|copy|comparte|share)\b", re.I)

QUESTION = re.compile(r"^\s*[¿]|\?\s*$|\b(?:necesito saber|quiero saber|i need to know|i want to know)\b|^\s*(?:qu[eé]|c[oó]mo|cu[aá]l(?:es)?|por qu[eé]|cu[aá]ndo|d[oó]nde|es |what|how|which|why|when|where|is |are |does |do |can )", re.I)
SCANNING = re.compile(r"\b(?:escanea|escaneo|scan|audita|audit|busca (?:malware|virus|secretos|vulnerabilidades|rootkits|credenciales expuestas|llaves expuestas)|"
                     r"look for (?:malware|secrets|vulnerabilities)|search for (?:malware|secrets|vulnerabilities)|en busca de|for (?:malware|secrets|vulnerabilities|exposed))\b", re.I)
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
_PATH = re.compile(r"(?<![\w.])((?:~|\.{1,2})?/[\w.\-/*]+|[\w.-]+/[\w.\-/]+|[\w-]+\.(?:log|txt|json|csv|yaml|yml|conf|cfg|ini|py|js|md|pcap|xml|html))")


def _segments(cmd: str) -> list[str]:
    """Part in commands by ;    respecting quotation marks."""
    try:
        lx = shlex.shlex(cmd.strip(), posix=True, punctuation_chars=";&|")
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return [p for p in re.split(r"\s*(?:\|\||&&|;|\|)\s*", cmd.strip()) if p]
    segs, actual = [], []
    for tk in toks:
        if tk and set(tk) <= set(";&|"):
            if actual:
                segs.append(" ".join(shlex.quote(x) for x in actual))
            actual = []
        else:
            actual.append(tk)
    if actual:
        segs.append(" ".join(shlex.quote(x) for x in actual))
    return segs


def _first_command(sec: str) -> str:
    try:
        toks = shlex.split(sec, posix=True)
    except ValueError:
        toks = sec.split()
    prior = ""
    while toks and (re.fullmatch(r"[A-Za-z_]\w*=\S*", toks[0]) or toks[0] in ("sudo", "nice", "time", "env", "nohup", "-E")):
        prior = toks[0]
        toks = toks[1:]
    if toks and toks[0].startswith("-") and prior == "sudo":
        return "sudo"   # sudo -l, sudo -v: sudo options, not another command
    return toks[0] if toks else prior


def is_command(text: str) -> bool:
    t = text.strip().strip("`")
    first = _first_command(_segments(t)[0]) if _segments(t) else ""
    if not first or re.match(r"^\s*(?:[¿]|por favor\b|please\b)", t, re.I) or INTENT_DEFENSIVE.match(t):
        return False
    if first in COMMANDS_RECOGNIZED or first.startswith(("./", "/", "~/", "$")):
        return True
    # Loose word + flags or shell characters: it looks like command even if we don't know it.
    return bool(re.fullmatch(r"[A-Za-z][\w.+-]*", first)) and bool(re.search(r"\s-{1,2}\w|[|;&<>$`]|^\S+\s+/", t))


# Interpreters and make run code that the agent does not see: only known uses are recognized.
_INTERPRETERS_OK = re.compile(r"^\s*(?:sudo\s+)?(?:python[23]?(?:\.\d+)?\s+-m\s+(?:pytest|unittest|pip|venv|pip_audit|bandit|json\.tool)\b|make\s+(?:test|tests|check|lint|audit)\b)")


def _segment_ok(sec: str) -> bool:
    cmd = _first_command(sec)
    if cmd in ("python", "python3", "make"):
        return bool(_INTERPRETERS_OK.match(sec))
    return cmd in COMMANDS_RECOGNIZED


def command_recognized(text: str) -> bool:
    segs = _segments(text.strip().strip("`"))
    return bool(segs) and all(_segment_ok(s) for s in segs)


def propose(text: str, trusted) -> list[tuple[A, dict]]:
    """Returns proposals (action, parameters). Empty list = "I don't understand the task"."""
    t = (text or "").strip()
    if not t:
        return []
    props: list[tuple[A, dict]] = []
    low = t.lower()

    # 1. literal shell command.
    if is_command(t):
        if command_recognized(t):
            return [(A.COMMAND_SIMULATED, {"command": t})]
        return []

    # 2. Defensive actions requested by the initiator.
    if re.search(r"\b(?:revoca|revocar|revoke)\b", low):
        m = re.search(r"\b(?:token|tok)[\s:#-]*([A-Za-z0-9_-]{4,})", t)
        props.append((A.REVOKE_TOKEN, {"token_id": m.group(1) if m else "session"}))
    if re.search(r"\b(?:bloquea|block|banea|ban|deny|niega)\b", low):
        ip = _IP.search(t)
        if ip:
            props.append((A.BLOCK_ACTION, {"fingerprint": f"ip:{ip.group(1)}", "reason": t[:200]}))
    if re.search(r"\b(?:cuarentena|quarantine|a[ií]sla el archivo|isolate the file)\b", low):
        r = _PATH.search(t)
        if r:
            props.append((A.QUARANTINE_FILE, {"path_": r.group(1), "reason": t[:200], "content": ""}))
    if re.search(r"\b(?:alerta|alert|notifica|notify|avisa)\b", low) and not SEND_NATURAL.search(t):
        props.append((A.ALERT, {"severity": "MEDIA", "message": t[:300]}))
    if SCANNING.search(t):
        r = _PATH.search(t)
        props.append((A.SCAN, {"target": r.group(1).lstrip("~/") if r else "files"}))
    if props:
        return props

    # 3. Sending to a trusted destination.
    destinations = destinations_in(t)
    if SEND_NATURAL.search(t) and destinations:
        if all(_domain_trusted(d, trusted) for d in destinations):
            mail = re.search(r"[\w.+-]+@[\w.-]+", t)
            return [(A.SEND, {"recipient": mail.group(0) if mail else destinations[0], "body_": t[:500]})]
        return []

    # 4. Consult a URL (read only, simulated).
    urls = urls_in(t)
    if urls and re.search(r"\b(?:descarga|consulta|abre|visita|revisa|lee|baja|fetch|get|download|open|visit|check|read)\b", low):
        url, schema, host = urls[0]
        if schema in ("http", "https") and _classify_host(host)[0] in ("PUBLIC", "NAME", "LOOPBACK"):
            return [(A.QUERY_URL, {"url": url})]
        return []

    # 5. Log reading or other non-sensitive resources.
    if re.search(r"\b(?:logs?|registros?|bit[aá]cora|journal|eventos|events|auth\.log|syslog|access\.log|error\.log)\b", low) and \
       re.search(r"\b(?:lee|l[eé]eme|revisa|analiza|muestra|mu[eé]strame|resume|busca|cuenta|read|review|analy[sz]e|show|summari[sz]e|search|count|check|tail|correlaciona|correlate|investiga|investigate|filtra|filter|extrae|extract)\b", low):
        r = _PATH.search(t)
        return [(A.READ_RESOURCE, {"resource_id": r.group(1) if r else "logs"}), (A.REPORT, {"summary": t[:300]})]

    # 6. Questions, explanations and safety tasks described in natural language.
    if QUESTION.search(t) or EXPLANATION.search(t) or INTENT_DEFENSIVE.search(t) or \
       re.search(r"\bhaz (?:un|una|el|la) (?:inventario|an[aá]lisis|reporte|informe|respaldo|resumen|escaneo|diagn[oó]stico|auditor[ií]a|revisi[oó]n)\b", t, re.I):
        return [(A.REPORT, {"summary": t[:300]})]
    return []
