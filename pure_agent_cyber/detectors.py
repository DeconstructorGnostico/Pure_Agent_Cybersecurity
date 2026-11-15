"""Detectors of the cyber security specialty.

Each detector returns findings typed (category, type, severity, evidence, verified fact supporting it). No detector executes anything or decides: it only observes. The decision is made `agent.py` with fixed rules.

All layers of `normalize_text.read` are read (original, normalized, URL, hex, base64, tags Unicode). So a command hidden in base64 or with zero width is seen.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlsplit, unquote

from .findings import Finding, Severity as S
from .normalize_text import Reading

I = re.IGNORECASE

# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

DOMAINS_TRUSTED_BY_DEFAULT = frozenset({
    "empresa.local", "corp.example", "github.com", "gitlab.com", "pypi.org",
    "files.pythonhosted.org", "registry.npmjs.org", "ubuntu.com", "debian.org",
    "python.org", "archive.ubuntu.com", "security.ubuntu.com", "docker.io",
    "localhost",
})

SERVICES_EXFIL = re.compile(
    r"(pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|file\.io|0x0\.st|webhook\.site|"
    r"requestbin|pipedream\.net|ngrok\.(io|app|dev)|ngrok-free\.app|interact\.sh|oast\.(fun|pro|live|site|online|me)|"
    r"burpcollaborator\.net|canarytokens|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|"
    r"anonfiles|mega\.nz|temp\.sh|termbin\.com|requestcatcher\.com|beeceptor\.com)", I)

EXPLANATION = re.compile(
    r"(\bqu[eé] (hace|significa|es)\b|\bexpl[ií]ca(me)?\b|\bwhat (does|is)\b|\bexplain\b|\bpor qu[eé] es (peligroso|malo)\b|"
    r"\bwhy is\b|\bdescribe\b|\bdocumenta\b|\bnunca (ejecutes|corras)\b|\bnever run\b|\bc[oó]mo (me protejo|detecto|evito|bloqueo|prevengo)\b|"
    r"\bhow (do|can) i (protect|defend|detect|prevent|block)\b|\bregla (de detecci[oó]n|sigma|yara)\b|\bdetection rule\b|"
    r"\b(escribe|crea|write|create) (una |a )?(regla|rule|firma|signature)\b|\bes seguro\b|\bis it safe\b|\bpara (un|una) (curso|clase|capacitaci[oó]n)\b)", I)

EXECUTION = re.compile(
    r"\b(ejec[uú]ta(lo|la)?|corre(lo|la)?|c[oó]rrelo|lanza(lo)?|run it|run this|execute|haz(lo)?|do it|apl[ií]ca(lo)?|pon(lo)? en marcha)\b", I)

DEFENSIVE = re.compile(
    r"\b(bloquea|bloquear|block|deny|drop|reject|niega|filtra|prohibe|proh[ií]be|denegar|blacklist|lista negra|"
    r"agrega una regla|add a rule)\b", I)


@dataclass
class Context:
    channel: str = "INTENT"
    domains_trusted: frozenset = DOMAINS_TRUSTED_BY_DEFAULT
    explanation: bool = False


def _domain_trusted(host: str, trusted: Iterable[str]) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in trusted)


def _in_search(text: str, start_: int) -> bool:
    """Does the pattern appear as text searched for by grep/rg/findstr, in quotation marks?"""
    prefix = text[max(0, start_ - 200):start_]
    return bool(re.search(r"\b(grep|egrep|zgrep|fgrep|rg|ag|ack|findstr|select-string|sigma|yara)\b[^|;\n]*['\"]\s*$", prefix, I))


# ---------------------------------------------------------------------------
# Table rules: (category, type, pattern, fact, severity)
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    category: str
    type_: str
    patron: re.Pattern
    fact_id: Optional[str]
    severity: S
    mention_degrade: bool = True    # in pregunta/explicación or in a low grep to LOW


def R(cat, type_, pat, fact, sev, flags=I, degrade=True):
    return Rule(cat, type_, re.compile(pat, flags), fact, sev, degrade)


_DESTINATION_ROOT = r"(?:/\*?|/\.\*|~/?\*?|\$\{?home\}?/?\*?|/(?:etc|usr|var|boot|bin|sbin|lib|lib64|home|root|opt|srv|sys|dev)/?\*?)(?=\s|$|;|&|\||\"|')"

RULES: list[Rule] = [
    # - Dangerous Commands--
    R("COMMAND_DANGEROUS", "rm_recursive_root",
      r"\brm\s+(?:(?:-[a-z]*[rRf][a-z]*|--recursive|--force|--no-preserve-root)\s+)+(?:[\"']?)" + _DESTINATION_ROOT, "KB-CMD-001", S.CRITICAL),
    R("COMMAND_DANGEROUS", "rm_root_destination_before", r"\brm\s+[\"']?/[\"']?\s+(?:-[a-z]*[rf][a-z]*\s*)+", "KB-CMD-001", S.CRITICAL),
    R("COMMAND_DANGEROUS", "no_preserve_root", r"--no-preserve-root", "KB-CMD-001", S.CRITICAL),
    R("COMMAND_DANGEROUS", "find_deleted_root", r"\bfind\s+/(?:\s|$)[^;\n]*(?:-delete|-exec\s+rm)", "KB-CMD-001", S.CRITICAL),
    R("COMMAND_DANGEROUS", "mkfs", r"\bmkfs(?:\.\w+)?\b[^\n;|]*\s/dev/", "KB-CMD-002", S.CRITICAL),
    R("COMMAND_DANGEROUS", "dd_a_disk", r"\bdd\b[^\n;|]*\bof=/dev/(?:sd|nvme|hd|xvd|vd|disk|mmcblk|rdisk)", "KB-CMD-003", S.CRITICAL),
    R("COMMAND_DANGEROUS", "fork_bomb", r"(\w+|:)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;?\s*\1", "KB-CMD-004", S.HIGH),
    R("COMMAND_DANGEROUS", "download_a_interpreter",
      r"\b(?:curl|wget|fetch)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k|c)?sh|python[23]?|perl|ruby|node|php)\b", "KB-CMD-005", S.HIGH),
    R("COMMAND_DANGEROUS", "interpreter_of_download",
      r"\b(?:(?:ba|z)?sh)\b\s+(?:-c\s+)?[\"']?(?:\$\(|<\(|`)\s*(?:curl|wget)\b", "KB-CMD-005", S.HIGH),
    R("COMMAND_DANGEROUS", "base64_a_interpreter", r"base64\s+(?:-d|--decode|-D)\b[^\n;]*\|\s*(?:sudo\s+)?(?:(?:ba|z)?sh|python[23]?|perl)\b", "KB-CMD-005", S.HIGH),
    R("COMMAND_DANGEROUS", "powershell_iex",
      r"(?:\biex\b|invoke-expression)[^\n]*(?:downloadstring|iwr|invoke-webrequest|net\.webclient)|(?:downloadstring|iwr|invoke-webrequest)[^\n]*\|\s*(?:iex|invoke-expression)", "KB-CMD-005", S.HIGH),
    R("COMMAND_DANGEROUS", "powershell_encoded", r"\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", "KB-CMD-005", S.HIGH),
    R("COMMAND_DANGEROUS", "chmod_777_system", r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|ugo\+rwx)\s+[\"']?" + _DESTINATION_ROOT, "KB-CMD-006", S.HIGH),
    R("COMMAND_DANGEROUS", "chown_recursive_root", r"\bchown\s+-R\s+\S+\s+[\"']?/(?=\s|$)", "KB-CMD-006", S.HIGH),
    R("COMMAND_DANGEROUS", "firewall_off",
      r"\bufw\s+disable\b|\biptables\s+(?:-F|--flush)\b|\biptables\s+-P\s+(?:INPUT|FORWARD)\s+ACCEPT|\bnft\s+flush\s+ruleset|"
      r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|ufw|iptables|nftables)\b|\bnetsh\s+(?:adv)?firewall\s+set\s+\w+\s+state\s+off|"
      r"\bset-netfirewallprofile\b[^\n]*-enabled\s+false|\bservice\s+(?:iptables|ufw|firewalld)\s+stop", "KB-CMD-007", S.HIGH),
    R("COMMAND_DANGEROUS", "defenses_off",
      r"\bsetenforce\s+0\b|\bset-mppreference\b[^\n]*-disable\w+\s+\$?(?:true|1)|\bsystemctl\s+(?:stop|disable|mask)\s+(?:apparmor|auditd|falcon-sensor|wazuh-agent|clamav-daemon|osqueryd|crowdstrike)\b|"
      r"\baa-teardown\b|\bauditctl\s+-D\b|\bauditctl\s+-e\s*0\b", "KB-CMD-008", S.HIGH),
    R("COMMAND_DANGEROUS", "writing_a_device",
      r">\s*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk)[a-z0-9]*\b|\b(?:shred|wipefs)\b[^\n;|]*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk)", "KB-CMD-009", S.CRITICAL),
    R("COMMAND_DANGEROUS", "deleted_windows",
      r"\bformat\s+[c-z]:|\b(?:del|erase)\s+(?:/[sqfa]\s+)+[\"']?[c-z]:\\(?:\*|\s|$|windows)|\b(?:rd|rmdir)\s+(?:/[sq]\s+)+[\"']?[c-z]:\\(?:\s|$|windows)|"
      r"remove-item\b[^\n]*-recurse[^\n]*[\"']?[c-z]:\\(?:\*|\s|$|[\"']|windows)|\bvssadmin\s+delete\s+shadows", "KB-CMD-010", S.CRITICAL),
    R("COMMAND_DANGEROUS", "delete_traces",
      r"\bhistory\s+-c\b|\bunset\s+histfile\b|\bwevtutil\s+cl\b|\bclear-eventlog\b|\brm\s+(?:-\w+\s+)*/var/log\b|"
      r"\b(?:shred|truncate\s+-s\s*0)\b[^\n;|]*/var/log/|>\s*/var/log/(?:auth|secure|syslog|wtmp|btmp|lastlog)|>\s*~/\.bash_history|\bjournalctl\s+--vacuum-time=1s", "KB-CMD-011", S.HIGH),
    R("COMMAND_DANGEROUS", "deleted_production",
      r"\bdrop\s+(?:database|schema)\b|\baws\s+s3\s+rb\b[^\n]*--force|\baws\s+s3\s+rm\b[^\n]*--recursive|\bkubectl\s+delete\s+(?:\w+\s+)?(?:--all\b|-A\b)|"
      r"\bkubectl\s+delete\s+(?:ns|namespace)\s+(?:kube-system|default|prod\w*)|\bterraform\s+destroy\b[^\n]*-auto-approve|\bgcloud\s+projects\s+delete\b|\bflushall\b|\bdropdb\b", "KB-CMD-012", S.HIGH),
    R("COMMAND_DANGEROUS", "deleted_language_natural",
      r"\b(?:borra|elimina|destruye|formatea|limpia|wipe|delete|erase|destroy|format|nuke)\b.{0,25}\b(?:todo el (?:disco|servidor|sistema|equipo)|todos los archivos del (?:servidor|sistema|disco|equipo)|"
      r"everything on the (?:server|disk|system|machine)|the (?:whole|entire) (?:disk|server|system|drive)|toda la base de datos|la base de datos de producci[oó]n|production database|"
      r"all (?:the )?backups|todos los (?:respaldos|backups)|el disco duro|the hard drive|el directorio ra[ií]z|the root directory)", "KB-CMD-001", S.HIGH),
    R("COMMAND_DANGEROUS", "deactivated_firewall_language_natural",
      r"\b(?:desactiva|apaga|deshabilita|quita|disable|turn off|shut down|stop)\b.{0,20}\b(?:el |the )?(?:firewall|cortafuegos|antivirus|defender|selinux|apparmor|edr|auditd)\b", "KB-CMD-007", S.HIGH),
    # --- Shell reverse ---
    R("SHELL_REVERSE", "dev_tcp", r"/dev/(?:tcp|udp)/[\w.\-]+/\d+", "KB-SHL-001", S.CRITICAL),
    R("SHELL_REVERSE", "nc_exec", r"\b(?:nc|ncat|netcat)\b[^\n;|]*\s-[a-z]*[ec]\s*[\"']?(?:/bin/|/usr/bin/)?(?:ba|z)?sh\b|\bncat\b[^\n]*--(?:exec|sh-exec)", "KB-SHL-001", S.CRITICAL),
    R("SHELL_REVERSE", "mkfifo_nc", r"\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat|telnet|openssl\s+s_client)\b", "KB-SHL-001", S.CRITICAL),
    R("SHELL_REVERSE", "socket_spawn", r"socket\.socket\([^\n]*(?:subprocess|pty\.spawn|os\.dup2)|fsockopen\s*\([^\n]*(?:exec|shell_exec|system|proc_open)|use\s+socket;[^\n]*exec", "KB-SHL-001", S.CRITICAL),
    R("SHELL_REVERSE", "socat_exec", r"\bsocat\b[^\n]*\b(?:exec|system):[^\n]*(?:sh|bash)", "KB-SHL-001", S.CRITICAL),
    R("SHELL_REVERSE", "ps_tcpclient", r"net\.sockets\.tcpclient\s*\(", "KB-SHL-001", S.CRITICAL),
    R("SHELL_REVERSE", "language_natural", r"\b(?:abre|crea|lanza|establece|open|spawn|start|give me)\b.{0,20}\b(?:una |a )?(?:shell inversa|reverse shell|bind shell|shell remota)\b", "KB-SHL-001", S.HIGH),
    # --- Scale of privileges ---
    R("ESCALATION_PRIVILEGES", "suid_interpreter",
      r"\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\s+[\"']?(?:/\S*/)?(?:bash|sh|dash|zsh|python[\d.]*|perl|ruby|find|vim?|nano|cp|env|less|awk|nmap|tar)\b", "KB-PRV-001", S.CRITICAL),
    R("ESCALATION_PRIVILEGES", "suid_generico", r"\bchmod\s+(?:[ugoa]*\+s|[46][0-7]{3})\s+\S+", "KB-PRV-001", S.HIGH),
    R("ESCALATION_PRIVILEGES", "setcap", r"\bsetcap\b[^\n]*cap_(?:setuid|sys_admin|dac_override|sys_ptrace)", "KB-PRV-001", S.HIGH),
    R("ESCALATION_PRIVILEGES", "sudoers_nopasswd", r"nopasswd\s*:\s*all|(?:>>|>|tee\s+(?:-a\s+)?)\s*/etc/sudoers(?:\.d/\S*)?\b|\bALL\s*=\s*\(ALL(?::ALL)?\)\s*ALL\b[^\n]*>>", "KB-PRV-002", S.CRITICAL),
    R("ESCALATION_PRIVILEGES", "passwd_uid0", r"(?:>>|tee\s+-a)\s*/etc/passwd\b|^\s*\w+:[^:\n]*:0:0:|\buseradd\b[^\n]*-o\s+-u\s*0\b|\busermod\b[^\n]*-u\s*0\b", "KB-PRV-002", S.CRITICAL, I | re.M),
    R("ESCALATION_PRIVILEGES", "group_admin",
      r"\busermod\s+-a?G\s+(?:\S+,)?(?:sudo|wheel|docker|root|admin|adm|lxd)\b|\bgpasswd\s+-a\s+\S+\s+(?:sudo|wheel|docker|root|lxd)\b|\badduser\s+\S+\s+(?:sudo|wheel|docker|lxd)\b|"
      r"\bnet\s+localgroup\s+administrat\w+\s+\S+\s+/add|add-localgroupmember\b[^\n]*administrat", "KB-PRV-004", S.HIGH),
    R("ESCALATION_PRIVILEGES", "escape_container",
      r"\bdocker\s+run\b[^\n]*(?:--privileged|-v\s*/:/|--volume[ =]/:/|--pid[ =]host|-v\s*/var/run/docker\.sock)|\bnsenter\b[^\n]*(?:-t\s*1\b|--target[ =]1\b)|\bchroot\s+/host\b", "KB-PRV-003", S.HIGH),
    R("ESCALATION_PRIVILEGES", "language_natural",
      r"\b(?:dame|hazme|convi[eé]rteme en|give me|make me|grant me|obt[eé]n|consigue|get)\b.{0,15}\b(?:root|administrador|admin rights|superusuario|sudo sin contrase[nñ]a|passwordless sudo)\b", None, S.MEDIA),
    R("ESCALATION_PRIVILEGES", "sudo_shell", r"\bsudo\s+(?:su\b|-s\b|-i\b|bash\b|sh\b)|\bsu\s+-?\s*root\b", None, S.MEDIA),
    R("ESCALATION_PRIVILEGES", "ld_preload_sudo", r"\bLD_PRELOAD=\S+\s+sudo\b|\bsudo\s+LD_PRELOAD=", "KB-PRV-001", S.HIGH),
    # --- Exploits of known CVE ---
    R("EXPLOIT_CVE", "log4shell", r"\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|corba|nds|nis|https?)\s*:", "KB-CVE-2021-44228", S.CRITICAL, degrade=False),
    R("EXPLOIT_CVE", "shellshock", r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;", "KB-CVE-2014-6271", S.CRITICAL, degrade=False),
    R("EXPLOIT_CVE", "sudo_uid_less_one", r"\bsudo\s+-u\s*#\s*(?:-1|4294967295)\b", "KB-CVE-2019-14287", S.HIGH),
    R("EXPLOIT_CVE", "pwnkit", r"\b(?:pwnkit|cve-2021-4034)\b[^\n]*\b(?:exploit|ejecuta|run|corre|lanza|compila)\b|\b(?:exploit|ejecuta|run|corre|lanza|compila)\b[^\n]*\b(?:pwnkit|cve-2021-4034)\b", "KB-CVE-2021-4034", S.HIGH),
    R("EXPLOIT_CVE", "dirtycow", r"\b(?:dirty\s*cow|dirtyc0w|cve-2016-5195)\b[^\n]*\b(?:exploit|ejecuta|run|corre|lanza|compila)\b|\b(?:exploit|ejecuta|run|corre|lanza|compila)\b[^\n]*\b(?:dirty\s*cow|dirtyc0w|cve-2016-5195)\b", "KB-CVE-2016-5195", S.HIGH),
    R("EXPLOIT_CVE", "eternalblue", r"(?<![a-z])(?:eternalblue|ms17-010|cve-2017-0144)\b[^\n]*\b(?:exploit|ejecuta|run|corre|lanza|contra|against)\b|\b(?:exploit|ejecuta|run|corre|lanza|usa|use)\b[^\n]*(?<![a-z])(?:eternalblue|ms17_010|ms17-010|cve-2017-0144)\b", "KB-CVE-2017-0144", S.CRITICAL),
    # --- Stealing of credentials (wrote) ---.
    R("THEFT_CREDENTIALS", "dump_credentials",
      r"\bmimikatz\b|\bsekurlsa\b|\blsass(?:\.exe|\.dmp)?\b[^\n]*(?:dump|procdump|minidump|comsvcs)|(?:procdump|comsvcs)[^\n]*lsass|\breg\s+save\s+hklm\\(?:sam|security|system)\b|"
      r"\bhashdump\b|\bsecretsdump\b|\bsecurity\s+(?:dump-keychain|find-generic-password\b[^\n]*-w)|\blazagne\b|\bunshadow\b", "KB-RUT-009", S.HIGH),
    R("THEFT_CREDENTIALS", "cookies_browser",
      r"(?:google[/\\ ]chrome|chromium|\.mozilla|firefox|brave|microsoft[/\\ ]edge)[^\n]*(?:cookies|login data|logins\.json|key4\.db|web data)\b|"
      r"\b(?:cookies|contrase[nñ]as guardadas|saved passwords|passwords)\b[^\n.]{0,25}\b(?:del navegador|of the browser|from (?:chrome|firefox|the browser|edge)|de (?:chrome|firefox|edge|brave))\b|"
      r"\b(?:roba|extrae|copia|dump|steal|extract|exporta)\b[^\n.]{0,25}\b(?:cookies|sesiones del navegador|browser sessions)\b", "KB-RUT-005", S.HIGH),
    R("THEFT_CREDENTIALS", "shadow", r"(?:\b(?:cat|less|more|head|tail|cp|scp|strings|base64|xxd|john|hashcat|unshadow|type|grep|awk|sed|tar|zip|nc|curl|python\S*|perl|vim?|nano|od)\b[^\n;|]*|[<@])/etc/(?:g?shadow|master\.passwd)\b|\bfile://+etc/shadow", "KB-RUT-002", S.HIGH),
    # --- Persistence ---
    R("PERSISTENCE", "authorized_keys_writing", r"(?:>>|>|tee\s+(?:-a\s+)?)\s*[\"']?(?:~|\$HOME|/root|/home/[\w.-]+)?/?\.ssh/authorized_keys2?\b", "KB-PER-001", S.HIGH),
    R("PERSISTENCE", "authorized_keys_language_natural",
      r"\b(?:agrega|a[nñ]ade|mete|pon|instala|add|append|insert|put)\b[^\n.]{0,60}\bauthorized_keys\b", "KB-PER-001", S.HIGH),
    R("PERSISTENCE", "backdoor_language_natural",
      r"\b(?:crea|instala|deja|planta|install|create|leave|plant|add)\b[^\n.]{0,20}\b(?:una |a )?(?:puerta trasera|backdoor|implante|implant|rootkit)\b", "KB-PER-002", S.HIGH),
]

# Payloads that become malicious a persistence (download, connection, code code).
PAYLOAD_RED = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet|mshta|bitsadmin|certutil)\b|/dev/tcp/|base64\s+(?:-d|--decode)|\bpython[23]?\s+-c\b|\bbash\s+-i\b|"
    r"\bpowershell\b[^\n]*-(?:e|enc|w\s+hidden|windowstyle\s+hidden)|https?://|\beval\b|\balias\s+sudo=|\bmkfifo\b|/tmp/\.\w+|\bxmrig\b|\bminerd?\b", I)

PERSIST_MECHANISM = [
    ("cron", re.compile(r"\bcrontab\s+(?:-\w+\s+)*-(?:\s|$)|\(\s*crontab\s+-l[^)]*;\s*echo|\bcrontab\s+-e\b|(?:>>|>|tee\s+(?:-a\s+)?)\s*/(?:etc/cron\S*|var/spool/cron\S*)|@reboot|\*\s+\*\s+\*\s+\*\s+\*", I)),
    ("rc_shell", re.compile(r"(?:>>|>|tee\s+(?:-a\s+)?)\s*[\"']?(?:~|\$HOME|/root|/home/[\w.-]+)?/?\.(?:bashrc|zshrc|profile|bash_profile|bash_login|zprofile|zshenv)\b|(?:>>|>|tee\s+(?:-a\s+)?)\s*/etc/(?:profile|bash\.bashrc|environment)\b|/etc/profile\.d/", I)),
    ("systemd", re.compile(r"/etc/systemd/system/\S+\.service|~/.config/systemd/user/|\bExecStart\s*=|\bsystemctl\s+(?:--user\s+)?enable\b", I)),
    ("rc_local", re.compile(r"/etc/rc\.local|/etc/init\.d/", I)),
    ("launchd", re.compile(r"(?:~/Library/|\$HOME/Library/|/Library/)Launch(?:Agents|Daemons)/|launch(?:agents|daemons)/\S*\.plist|\blaunchctl\s+(?:load|bootstrap)\b", I)),
    ("windows_run", re.compile(
        r"\\(?:software\\)?(?:microsoft\\)?(?:windows\\)?(?:currentversion\\)?run(?:once)?\b|"
        r"\b(?:reg(?:\.exe)?\s+add|new-itemproperty)\b[^\n]*\\run(?:once)?\b|"
        r"\bschtasks\s+/create\b|\bregister-scheduledtask\b|__eventfilter|\\start menu\\programs\\startup", I)),
]


# ---------------------------------------------------------------------------
# Sensitive and Secret Routes
# ---------------------------------------------------------------------------

PATHS_SENSITIVE = [
    ("key_ssh", re.compile(
        r"(?<![\w])(?:~|\$HOME|/root|/home/[\w.-]+)?[/\\]?\.ssh(?:[/\\](?:id_[\w-]+|[\w.-]*_key|identity))?\b(?!\.pub)", I), "KB-RUT-001"),
    ("dotenv", re.compile(r"(?:^|[\s/'\"=:@<])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?(?=$|[\s'\";|&)])", I), "KB-RUT-003"),
    ("credentials_cloud", re.compile(r"\.aws[/\\](?:credentials|config)\b|\.config/gcloud\b|application_default_credentials\.json|\.azure[/\\]|\.kube[/\\]config\b|\.docker[/\\]config\.json|serviceaccount/token\b|/var/run/secrets/", I), "KB-RUT-004"),
    ("tokens_text_plane", re.compile(r"\.git-credentials\b|(?:^|[\s/~])\.netrc\b|\.npmrc\b|\.pypirc\b|\.pgpass\b|\.my\.cnf\b|\bwp-config\.php\b", I), "KB-RUT-006"),
    ("environ_process", re.compile(r"/proc/(?:self|\d+|\*)/environ\b", I), "KB-RUT-007"),
    ("shadow", re.compile(r"/etc/(?:g?shadow|master\.passwd)\b", I), "KB-RUT-002"),
    ("keys_language_natural", re.compile(
        r"\b(?:mis |las |tus |sus |the |my |your |all )?(?:llaves? privadas?|private keys?|llaves? ssh|ssh keys?|credenciales de (?:aws|la nube|gcp|azure)|aws credentials|tokens? de (?:github|acceso|api)|api keys?|llaves? de api|claves? de api|secret keys?|contrase[nñ]as? (?:del sistema|de los usuarios)|password hashes)\b", I), None),
]

VERB_CONTENT = re.compile(
    r"\b(?:cat|less|more|head|tail|type|get-content|gc|strings|xxd|hexdump|od|base64|cp|copy|scp|rsync|tar|zip|7z|gzip|open|read|lee|leer|l[eé]e(?:lo|la|me)?|"
    r"muestra(?:me|lo)?|ens[eé][nñ]a(?:me)?|imprime|print|dump|vuelca|copia|extrae|extract|dame|give me|show(?: me)?|display|env[ií]a|manda|send|sube|upload|"
    r"exfiltra|exfiltrate|grep|awk|sed|python\S*|vim?|nano|code|dime (?:el|lo que)|tell me what|what(?:'s| is) in|qu[eé] (?:hay|dice|contiene)|contenido de|contents of|steal|roba)\b", I)

VERB_METADATA = re.compile(r"^\s*(?:sudo\s+)?(?:ls|stat|chmod|chown|file|getfacl|test|ssh-keygen|ssh-add|du|wc\s+-l)\b", I)

SECRETS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "KB-SEC-001"),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "KB-SEC-002"),
    ("key_private", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "KB-SEC-003"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "KB-SEC-004"),
    ("slack_stripe", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk_live_[A-Za-z0-9]{16,}\b"), "KB-SEC-005"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "KB-SEC-006"),
]


def secrets_in(text: str) -> list[tuple[str, str, str]]:
    """(type, masked fragment, fact_id) for each secret with known formatting."""
    out = []
    for type_, pat, hid in SECRETS:
        for m in pat.finditer(text or ""):
            frag = m.group(0)
            out.append((type_, frag[:6] + "…" + ("" if len(frag) < 12 else frag[-2:]), hid))
    return out


# ---------------------------------------------------------------------------
# Network: URLs, hosts, SSRF and exfiltration destinations
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftp|gopher|dict|file|ldap|ldaps|tftp|jar|netdoc)://[^\s'\"<>`)]+", I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_SCP_RE = re.compile(r"\b(?:scp|rsync|sftp)\b[^\n;|]*\s(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+|\d{1,3}(?:\.\d{1,3}){3}):", I)
_NC_RE = re.compile(r"\b(?:nc|ncat|netcat|telnet|socat)\b\s+(?:-\w+\s+)*([\w-]+(?:\.[\w-]+)+|\d{1,3}(?:\.\d{1,3}){3})\s+\d{2,5}\b", I)
_BARE_HOST_IP = re.compile(r"(?<![\w.])(169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254|0x[a-f0-9]{8}|2852039166|0251\.0376\.0251\.0376)(?![\w.])", I)

METADATA_HOSTS = {"169.254.169.254": "KB-RED-001", "fd00:ec2::254": "KB-RED-001",
                   "metadata.google.internal": "KB-RED-002", "metadata": "KB-RED-002",
                   "100.100.100.200": "KB-RED-002", "metadata.azure.com": "KB-RED-001",
                   "169.254.170.2": "KB-RED-001"}


# Real internal networks (RFC 1918, CGNAT, ULA). Documentation networks (TEST-NET) are treated as public.
_NETWORKS_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def _ip_from_host(host: str) -> Optional[ipaddress._BaseAddress]:
    h = (host or "").strip("[]").lower()
    if not h:
        return None
    # nip.io / sslip.io with embedded IP
    m = re.match(r"^(?:[\w-]+\.)?(\d{1,3}(?:[.-]\d{1,3}){3})\.(?:nip\.io|xip\.io|sslip\.io|nip\.direct)$", h)
    if m:
        h = m.group(1).replace("-", ".")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", h):
            return ipaddress.ip_address(int(h))
        if re.fullmatch(r"0x[0-9a-f]{1,8}", h):
            return ipaddress.ip_address(int(h, 16))
        parts = h.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]*|\d+", p) for p in parts):
            nums = [int(p, 16) if p.startswith("0x") else (int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)) for p in parts]
            if all(0 <= n <= 255 for n in nums):
                return ipaddress.ip_address(".".join(map(str, nums)))
    except ValueError:
        return None
    return None


def _classify_host(host: str) -> tuple[str, Optional[str]]:
    """→ (class done) with class METADATA  LOOPBACK  PRIVATE  PUBLIC  NAME."""
    h = (host or "").strip("[]").lower().rstrip(".")
    if h in METADATA_HOSTS:
        return "METADATA", METADATA_HOSTS[h]
    ip = _ip_from_host(h)
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        s = str(ip)
        if s in METADATA_HOSTS:
            return "METADATA", METADATA_HOSTS[s]
        if ip.is_link_local:
            return "METADATA", "KB-RED-001"
        if ip.is_loopback or s == "0.0.0.0" or ip.is_unspecified:
            return "LOOPBACK", None
        if any(ip in red for red in _NETWORKS_PRIVATE if ip.version == red.version):
            return "PRIVATE", None
        return "PUBLIC", None
    if h in ("localhost",) or h.endswith(".localhost"):
        return "LOOPBACK", None
    if h.endswith((".internal", ".local", ".lan", ".corp", ".intranet")):
        return "PRIVATE", None
    return "NAME", None


def urls_in(text: str) -> list[tuple[str, str, str]]:
    """(url, schema, host) for each URL; resolve user@host and IPv6 brackets."""
    out = []
    for m in _URL_RE.finditer(text or ""):
        url = m.group(0).rstrip(".,;")
        try:
            sp = urlsplit(url)
            host = sp.hostname or ""
            if not host and sp.netloc:
                host = sp.netloc.rsplit("@", 1)[-1].split(":")[0]
        except ValueError:
            host = ""
            sp = None
        schema = url.split(":", 1)[0].lower()
        out.append((url, schema, unquote(host)))
    return out


_HOST_AFTER_VERB = re.compile(
    r"\b(?:a|hacia|to|onto|into|en)\s+(?:https?://)?([\w-]+(?:\.[\w-]+)+)(?:[/\s:,]|$)|"
    r"\b(?:subi[eé]ndola|subi[eé]ndolo|subiendo|envi[aá]ndola|envi[aá]ndolo|enviando)\s+(?:a|en|hacia|to)\s+(?:https?://)?([\w-]+(?:\.[\w-]+)+)", I)
_S3_GS = re.compile(r"\b(?:s3|gs)://([\w.-]+)", I)
_RCLONE_REMOTE = re.compile(r"\brclone\s+(?:copy|sync|move|copyto|moveto)\s+\S+\s+([\w.-]+):", I)
_SMB_RE = re.compile(r"\bsmbclient\s+//([^/\s]+)/", I)


def destinations_in(text: str) -> list[str]:
    """Possible external destinations: hosts of URL, mail, scp/rsync, nc, s3/gs, rclone, smb."""
    d = [h for _, _, h in urls_in(text) if h]
    d += [m.group(1) for m in _EMAIL_RE.finditer(text or "")]
    d += [m.group(1) for m in _SCP_RE.finditer(text or "")]
    d += [m.group(1) for m in _NC_RE.finditer(text or "")]
    for m in _HOST_AFTER_VERB.finditer(text or ""):
        d.append(m.group(1) or m.group(2))
    d += [m.group(1) for m in _S3_GS.finditer(text or "")]
    d += [m.group(1) for m in _RCLONE_REMOTE.finditer(text or "")]
    d += [m.group(1) for m in _SMB_RE.finditer(text or "")]
    return [x.lower() for x in d if x]


# Sending/uploading signals for data.
SEND_DATA = re.compile(
    r"\bwget\b[^\n;]*--post-(?:file|data)|\b(?:scp|rsync|sftp)\b[^\n;|]*\s\S+:\S*|\b(?:nc|ncat|netcat|socat)\b[^\n]*(?:<|\|)|[|]\s*(?:nc|ncat|netcat)\b|"
    r"\b(?:invoke-webrequest|iwr|invoke-restmethod|irm)\b[^\n]*(?:-method\s+(?:post|put)|-infile|-body)|\bsmbclient\b[^\n]*\bput\b|\bftp\b[^\n]*\bput\b|\bpython[23]?\s+-m\s+http\.server\b|"
    r"\b(?:dig|nslookup|host)\b[^\n]*(?:\$\(|`)|\bmail\b[^\n]*-s[^\n]*<|\bsendmail\b|\baws\s+s3\s+(?:cp|sync|mv)\s+(?!s3://)\S+\s+s3://|\bgsutil\s+cp\s+(?!gs://)\S+\s+gs://|"
    r"\brclone\s+(?:copy|sync)\b|\bgit\s+push\s+https?://|\bpython\S*\s+-m\s+http\.server\b", re.IGNORECASE)

# curl goes separately and distinguishes capitals: -F (form) and -T (up) are not -f (fail) nor -t.
SEND_CURL = re.compile(
    r"\b(?i:curl)\b[^\n;]*(?:\s-d\b|\s--data(?:-binary|-raw|-urlencode|-ascii)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|"
    r"\s-X\s*(?i:POST|PUT)\b|\s--request\s+(?i:POST|PUT)\b|@-|\s@\S|\s-[a-zA-Z]*d\s)")

SEND_NATURAL = re.compile(
    r"\b(?:env[ií]a|manda|m[aá]nda|reenv[ií]a|sube|s[uú]be|comparte|publica|pega|p[eé]ga|transfiere|exfiltra|filtra)(?:me|nos|le|les|te)?(?:lo|la|los|las)?\b|\b(?:send(?: it| them| this| that)?|e-?mail(?: it)?|forward(?: it)?|upload(?: it)?|post(?: it)?|"
    r"share(?: it)?|paste(?: it)?|exfiltrate|copy it|leak|filtra(?:lo|la)?|transmit|push it)\b", re.IGNORECASE)

DATA_LOAD = re.compile(
    r"\b(?:archivo|archivos|fichero|file|files|base de datos|database|db|dump|volcado|backup|respaldo|registros|logs?|clientes|customers|usuarios|users|"
    r"todo|everything|contenido|contents|output|salida|resultado|eso|esto|that|this|it|them|lo|la|los|las|tabla|table|c[oó]digo fuente|source code|repositorio|repo|"
    r"llaves?|keys?|credenciales|credentials|secretos|secrets|tokens?|contrase[nñ]as|passwords|cookies|historial|history)\b|[~/]\S+|@\S+|\s<\s*\S+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Injecting prompts
# ---------------------------------------------------------------------------

INJECTION_PHRASES = re.compile(
    r"(\bignor(?:a|e|ar|en)\b.{0,30}\b(?:instrucciones|instructions|reglas|rules|indicaciones|directives|guidelines|lo anterior|above|previous|prior)\b|"
    r"\bdisregard\b.{0,30}\b(?:instructions|rules|above|previous|prior|guidelines|request|task|question)\b|"
    r"\b(?:instead|en su lugar|en vez de eso)\b[,;:]?\s*(?:please\s+|por favor\s+)?(?:visit|send|run|execute|open|upload|forward|visita|env[ií]a|ejecuta|abre|sube|reenv[ií]a)\b|"
    r"\bignora (?:la petici[oó]n|lo que (?:pidi[oó]|pide) el usuario|al usuario)\b|"
    r"\bolvida\b.{0,25}\b(?:instrucciones|reglas|lo anterior|todo lo que)\b|\bforget\b.{0,25}\b(?:instructions|rules|everything|above)\b|"
    r"\bnuevas instrucciones\b|\bnew instructions\b|\binstrucciones (?:del sistema|ocultas|nuevas)\b|\bupdated instructions\b|"
    r"(?:^|[\[<#(\s])(?:system|sistema|admin|developer|root)\s*(?:prompt|override|message|mensaje)?\s*[:\]>)]|<\|im_start\|>|<\|system\|>|\[/?inst\]|"
    r"\bahora eres\b|\byou are now\b|\bact[uú]a como si no tuvieras\b|\bact as if you have no\b|\bdo anything now\b|\bmodo (?:desarrollador|dios|sin restricciones|dan)\b|\b(?:developer|god|jailbreak|dan) mode\b|"
    r"\bno (?:se lo )?(?:le )?digas (?:nada )?al usuario\b|\bdon'?t (?:tell|inform|mention (?:this )?to) the user\b|\bsin que el usuario (?:lo )?(?:sepa|note|se entere)\b|\bwithout (?:telling|informing|alerting) the user\b|"
    r"\bdo not (?:tell|inform|alert) the user\b|\b(?:nota|mensaje|instrucci[oó]n) para (?:la ia|el asistente|el agente|el modelo|la inteligencia artificial)\b|"
    r"\b(?:note|message|instruction)s? (?:to|for) (?:the )?(?:ai|assistant|agent|model|llm)\b|\bsi eres (?:una ia|un modelo|un asistente|un agente)\b|\bif you are an? (?:ai|llm|language model|assistant|agent)\b|"
    r"\b(?:to|for) (?:the )?(?:ai|llm) (?:reading|processing|summarizing) this\b|\b(?:asistente|assistant|agente|agent|ai|ia)\s*[:,]\s*(?:debes|tienes que|you must|you should|please|por favor|ejecuta|run|send|env[ií]a)\b|"
    r"\boverride\b.{0,20}\b(?:safety|seguridad|rules|reglas|policy|pol[ií]tica)\b|\bprioridad m[aá]xima\b.{0,40}\b(?:ejecuta|env[ií]a|run|send)\b|\bhighest priority\b.{0,40}\b(?:execute|run|send)\b|"
    r"\brevela (?:tu|el) (?:prompt|system prompt|instrucciones)\b|\breveal (?:your|the) (?:system )?prompt\b)", re.IGNORECASE | re.S)

IMPERATIVE_AGENT = re.compile(
    r"\b(?:ejecuta|corre|lanza|run|execute|env[ií]a|manda|send|sube|upload|borra|elimina|delete|descarga|download|instala|install|"
    r"visita|visit|abre|open|lee|read|copia|copy|reenv[ií]a|forward|llama a|call|haz clic|click|aprueba|approve|transfiere|transfer|paga|pay)\b", re.IGNORECASE)

HIDDEN_HTML = re.compile(r"<!--(.*?)-->|<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white))[^\"']*[\"'][^>]*>(.*?)<", re.IGNORECASE | re.S)


# ---------------------------------------------------------------------------
# Web: SQLi, command injection, traversal path
# ---------------------------------------------------------------------------

SQLI = [
    re.compile(r"['\"`]\)?\s*(?:or|and|\|\|)\s+(['\"]?)(\w+)\1\s*(?:=|like)\s*\1\2\b", re.I),
    re.compile(r"['\"`]\)?\s*(?:or|and)\s+\d+\s*=\s*\d+", re.I),
    re.compile(r"\bor\s+1\s*=\s*1\b|\bor\s+true\b\s*(?:--|#)|['\"]\s*or\s*(['\"])\1\s*=\s*\1", re.I),
    re.compile(r"\bunion\b(?:\s+all)?\s+(?:distinct\s+)?select\b", re.I),
    re.compile(r"['\"`]\)?\s*;\s*(?:drop|delete|insert|update|shutdown|exec|declare|truncate|alter|create)\b", re.I),
    re.compile(r"['\"`]\)?\s*(?:--|#|/\*)", re.I),
    re.compile(r"\b(?:sleep|pg_sleep)\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|\bwaitfor\s+delay\b|\bdbms_pipe\.receive_message\b", re.I),
    re.compile(r"\bxp_cmdshell\b|\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bextractvalue\s*\(|\bupdatexml\s*\(", re.I),
    re.compile(r"\binformation_schema\.(?:tables|columns)\b", re.I),
]
CONTEXT_SQL_ADMIN = re.compile(r"^\s*(?:select|insert|update|delete|create|alter|with|explain|show|describe|psql|mysql|sqlite3)\b", re.I)

CMDI_VALUE = re.compile(
    r"(?:=|:\s|^|[\"'])\s*[\w.\-/:]*\s*(?:;|\|\|?|&&|\n|%0a|%0d|%3b|%7c|%26%26)\s*(?:id|whoami|uname|cat|ls|nc|ncat|curl|wget|bash|sh|rm|ping|nslookup|python[23]?|perl|powershell|cmd|net\s+user|sleep|echo)\b",
    re.I | re.M)
CMDI_SUBSHELL = re.compile(r"(?:\$\(|`)\s*(?:curl|wget|nc|ncat|bash\s+-i|sh\s+-i|rm\s+-|cat\s+/etc/(?:passwd|shadow)|python[23]?\s+-c|perl\s+-e|base64\s+-d)", re.I)
CMDI_SUBSHELL_RECON = re.compile(r"(?:\$\(|`)\s*(?:id|whoami|uname(?:\s+-a)?|hostname)\s*(?:\)|`)", re.I)
CONTEXT_PARAM = re.compile(
    r"\b(?:par[aá]metro|parameter|param|campo|field|input|entrada|formulario|form|query|valor|value|filename|nombre de archivo|host|hostname|usuario|username|"
    r"b[uú]squeda|search|url|endpoint|api|payload|header|cabecera|cookie|user-agent|petici[oó]n|request|post|get)\b|[?&]\w+=|\b\w+=", re.I)

TRAVERSAL_ENCODED = re.compile(
    r"%2e%2e(?:%2f|%5c|/|\\)|\.\.%2f|\.\.%5c|%252e%252e|%c0%ae|%c0%af|%e0%80%af|\.{3,4}/{1,2}|\.\.;/|\.\.\\\\?\.\.|%u002e", re.I)
TRAVERSAL = re.compile(r"(?:\.\.[/\\]){2,}")
TRAVERSAL_TARGET = re.compile(r"(?:\.\.[/\\])+(?:etc[/\\](?:passwd|shadow|hosts|sudoers)|windows[/\\](?:win\.ini|system32)|proc[/\\]self|root[/\\]|\.ssh|\.env|\.aws|boot\.ini|web\.config|wp-config)", re.I)
NULL_BYTE = re.compile(r"%00|\\x00|\\0(?=\.\w{2,4}\b)")


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------

@dataclass
class _Accumulator:
    findings: list[Finding] = field(default_factory=list)

    def add(self, h: Finding) -> None:
        for i, x in enumerate(self.findings):
            if x.category == h.category and x.type_ == h.type_:
                if h.severity > x.severity:
                    self.findings[i] = h
                return
        self.findings.append(h)


def _degrade(h: Finding, note: str) -> Finding:
    h.severity = min(h.severity, S.LOW)
    h.note = note
    return h


def _rules_table(layers, ctx: Context, acc: _Accumulator) -> None:
    for layer, t in layers:
        for r in RULES:
            m = r.patron.search(t)
            if not m:
                continue
            h = Finding(r.category, r.type_, r.severity, m.group(0), r.fact_id, ctx.channel, layer)
            if r.mention_degrade and ctx.channel == "INTENT":
                if ctx.explanation:
                    _degrade(h, "mención en pregunta o explicación; no se pide ejecutar")
                elif _in_search(t, m.start()):
                    _degrade(h, "el patrón es el texto que se busca (grep), no un comando")
            acc.add(h)


def _persistence(layers, ctx, acc):
    for layer, t in layers:
        for name_, pat in PERSIST_MECHANISM:
            m = pat.search(t)
            if not m:
                continue
            if name_ == "cron" and re.search(r"\bcrontab\s+-l\b\s*(?:$|\||>)", t) and not re.search(r";\s*echo|\|\s*crontab\s+-", t):
                continue  # only list
            payload = PAYLOAD_RED.search(t)
            if payload:
                hid = "KB-PER-003" if name_ == "rc_shell" else "KB-PER-002"
                h = Finding("PERSISTENCE", f"{name_}_with_load", S.HIGH, f"{m.group(0)} … {payload.group(0)}", hid, ctx.channel, layer)
                if ctx.explanation and ctx.channel == "INTENT":
                    _degrade(h, "mención en pregunta o explicación")
                acc.add(h)
            elif name_ in ("windows_run", "launchd", "rc_local"):
                acc.add(Finding("PERSISTENCE", name_, S.MEDIA, m.group(0), None, ctx.channel, layer,
                                 "automatic boot mechanism without obvious load: I don't know if it is legitimate"))


def _sensitive_and_secrets(layers, ctx, acc, session_readings: list) -> None:
    for layer, t in layers:
        # Remove "-i path_key" (using a key as identity is not reading it).
        t_without_i = re.sub(r"\s-i\s+\S+", " ", t)
        for type_, pat, hid in PATHS_SENSITIVE:
            m = pat.search(t_without_i)
            if not m:
                continue
            # After .ssh, if the path ends in .pub it is a public key: it is not secret.
            queue = t_without_i[m.end():m.end()+40]
            if m.group(0).rstrip().endswith(".pub") or re.match(r"[/\\][^\s;|&]*\.pub\b", queue):
                continue
            phrase = t_without_i
            metadata = bool(VERB_METADATA.search(phrase)) and not re.search(r"[|>]|&&|;", phrase)
            content = bool(VERB_CONTENT.search(phrase)) or bool(re.search(r"[<@]\s*\S*" + re.escape(m.group(0).strip()), phrase))
            if metadata and not re.search(r"\b(?:cat|less|more|head|tail|type|cp|scp|base64|xxd|strings)\b", phrase, re.I):
                continue
            if type_ == "keys_language_natural":
                if not content:
                    continue
                if re.search(r"\b(?:rota|rotar|rotate|revoca|revoke|regenera|regenerate|genera|generate|crea|create|cambia|change|renueva|renew|elimina las expuestas|deshabilita|disable|escanea|scan|busca|search|find|detecta|detect|audita|audit|revisa si|check if|lista los nombres|list the names)\b", phrase, re.I):
                    continue
                h = Finding("THEFT_CREDENTIALS", "asks_secrets", S.MEDIA, m.group(0), None, ctx.channel, layer,
                             "asks for secrets without concrete route: I don't know if it is legitimate")
            else:
                if not content:
                    continue
                sev = S.HIGH if type_ == "shadow" else S.MEDIA
                h = Finding("THEFT_CREDENTIALS", f"reading_{type_}", sev, m.group(0), hid, ctx.channel, layer,
                             "reading a sensitive resource; if it is then sent, it is theft")
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            else:
                session_readings.append((h.type_, m.group(0).strip(), hid))
            acc.add(h)
        for type_, frag, hid in secrets_in(t):
            sev = S.MEDIA
            acc.add(Finding("THEFT_CREDENTIALS", f"secret_{type_}", sev, frag, hid, ctx.channel, layer,
                             "secret with known format present in the text"))


def _red(layers, ctx: Context, acc: _Accumulator, there_is_reading_sensitive: bool) -> None:
    for layer, t in layers:
        defensive = bool(DEFENSIVE.search(t)) and bool(re.search(r"\b(?:ufw|iptables|nft|firewall|cortafuegos|regla|rule|waf|security group|grupo de seguridad|egress|salida)\b", t, re.I))
        hosts = [(u, e, h) for (u, e, h) in urls_in(t)]
        for m in _BARE_HOST_IP.finditer(t):
            hosts.append((m.group(0), "", m.group(1)))
        for url, schema, host in hosts:
            class_, hid = _classify_host(host)
            if class_ == "METADATA":
                h = Finding("SSRF", "metadata_cloud", S.CRITICAL, url, hid, ctx.channel, layer)
                if defensive or (ctx.explanation and ctx.channel == "INTENT"):
                    _degrade(h, "se menciona para bloquearlo o explicarlo")
                acc.add(h)
            elif schema in ("file", "gopher", "dict", "ldap", "ldaps", "tftp", "jar", "netdoc"):
                if schema == "ldap" and "jndi" in t.lower():
                    continue
                h = Finding("SSRF", f"schema_{schema}", S.HIGH, url, "KB-RED-003", ctx.channel, layer)
                if ctx.explanation and ctx.channel == "INTENT":
                    _degrade(h, "mención en pregunta o explicación")
                acc.add(h)
            elif class_ in ("LOOPBACK", "PRIVATE") and ctx.channel == "DATA":
                acc.add(Finding("SSRF", "red_internal_from_data", S.MEDIA, url, None, ctx.channel, layer,
                                 "an external data points to the internal network"))
            elif class_ in ("LOOPBACK", "PRIVATE") and CONTEXT_PARAM.search(t) and re.search(r"\b(?:url|webhook|callback|redirect|next|image|imagen|fetch|proxy)\s*[=:]", t, re.I):
                acc.add(Finding("SSRF", "red_internal_in_param", S.MEDIA, url, None, ctx.channel, layer,
                                 "URL parameter pointing to the internal network"))
        # Exfiltration
        send_cmd = SEND_CURL.search(t) or SEND_DATA.search(t)
        send_nat = SEND_NATURAL.search(t)
        destinations = destinations_in(t)
        external = [d for d in destinations if not _domain_trusted(d, ctx.domains_trusted)
                    and _classify_host(d)[0] in ("PUBLIC", "NAME")]
        service = SERVICES_EXFIL.search(t)
        if service and (send_cmd or send_nat or ctx.channel == "DATA"):
            h = Finding("EXFILTRACION", "service_of_exfiltracion", S.HIGH, service.group(0), "KB-RED-004", ctx.channel, layer)
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            acc.add(h)
        if (send_cmd or send_nat) and external:
            load = DATA_LOAD.search(t)
            if there_is_reading_sensitive:
                h = Finding("EXFILTRACION", "secret_a_external", S.CRITICAL, f"{(send_cmd or send_nat).group(0)[:60]} → {external[0]}",
                             "KB-RED-005", ctx.channel, layer, "sensitive data towards a domain outside the trusted list")
            elif send_cmd or load:
                h = Finding("EXFILTRACION", "data_a_external", S.HIGH, f"{(send_cmd or send_nat).group(0)[:60]} → {external[0]}",
                             "KB-RED-005", ctx.channel, layer)
            else:
                h = Finding("EXFILTRACION", "message_a_external", S.MEDIA, external[0], None, ctx.channel, layer,
                             "sending to an unknown destination without clear data: I don't know if it is legitimate")
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            acc.add(h)
        elif send_cmd and re.search(r"\b(?:dig|nslookup|host)\b[^\n]*(?:\$\(|`)", t, re.I):
            acc.add(Finding("EXFILTRACION", "exfil_dns", S.HIGH, send_cmd.group(0), "KB-RED-005", ctx.channel, layer))


def _web(layers, ctx, acc):
    for layer, t in layers:
        if ctx.channel == "INTENT" and re.match(r"^\s*(?:sudo\s+)?(?:grep|egrep|zgrep|fgrep|rg|ag|ack|findstr|select-string|awk)\b", t, re.I):
            continue  # looking for attack patterns in own logs is defensive work
        admin_sql = bool(CONTEXT_SQL_ADMIN.search(t))
        for i, pat in enumerate(SQLI):
            m = pat.search(t)
            if not m:
                continue
            # A DBA typing SQL normal is not injection: only tautologies count,
            # UNION, comments after quote and functions of tiempo/file.
            if admin_sql and i in (5, 8):
                continue
            h = Finding("INJECTION_SQL", f"sqli_{i}", S.HIGH, m.group(0), "KB-WEB-001", ctx.channel, layer)
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            acc.add(h)
            break
        m = CMDI_VALUE.search(t)
        if m and (CONTEXT_PARAM.search(t) or re.search(r"%0a|%3b|%7c|%26", m.group(0), re.I) or re.search(r"\d+\.\d+\.\d+\.\d+\s*[;|&]", m.group(0))):
            if not re.match(r"^\s*(?:sudo\s+)?(?:ps|ls|cat|grep|journalctl|systemctl|docker|kubectl|tail|df|du|find|echo|git|cd|make|pip|npm|apt|dnf|yum|brew)\b", t, re.I) or re.search(r"[=?]\S*\s*(?:;|\|\||&&|%0a|%3b)", m.group(0), re.I):
                h = Finding("INJECTION_COMMANDS", "metacaracter_in_param", S.HIGH, m.group(0), "KB-WEB-002", ctx.channel, layer)
                if ctx.explanation and ctx.channel == "INTENT":
                    _degrade(h, "mención en pregunta o explicación")
                acc.add(h)
        m = CMDI_SUBSHELL.search(t)
        if m:
            h = Finding("INJECTION_COMMANDS", "subshell_dangerous", S.HIGH, m.group(0), "KB-WEB-002", ctx.channel, layer)
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            acc.add(h)
        m = CMDI_SUBSHELL_RECON.search(t)
        if m and CONTEXT_PARAM.search(t):
            acc.add(Finding("INJECTION_COMMANDS", "subshell_in_param", S.HIGH, m.group(0), "KB-WEB-002", ctx.channel, layer))
        # Path traversal
        m = TRAVERSAL_ENCODED.search(t) or TRAVERSAL_TARGET.search(t)
        if m:
            h = Finding("PATH_TRAVERSAL", "traversal", S.HIGH, m.group(0), "KB-WEB-003", ctx.channel, layer)
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            acc.add(h)
        else:
            m = TRAVERSAL.search(t)
            if m and len(re.findall(r"\.\.[/\\]", m.group(0))) >= 3 and CONTEXT_PARAM.search(t):
                acc.add(Finding("PATH_TRAVERSAL", "traversal_deep", S.MEDIA, m.group(0), None, ctx.channel, layer,
                                 "rise of several levels in one parameter: I don't know where it reaches"))
        m = NULL_BYTE.search(t)
        if m and CONTEXT_PARAM.search(t):
            acc.add(Finding("PATH_TRAVERSAL", "byte_null", S.HIGH, m.group(0), "KB-WEB-003", ctx.channel, layer))


def _log4j_normalize(t: str) -> str:
    # {lower:j}/{upper:j}/{::-j}/{env:X:-j}/{date:'j} → j (various turns)
    for _ in range(6):
        new = re.sub(r"\$\{(?:lower|upper|::|env:[^:}]*:|sys:[^:}]*:|date):?-?'?([^${}']{1,4})'?\}", r"\1", t, flags=re.I)
        if new == t:
            break
        t = new
    return t


def _injection_prompt(layers, lec_flags, ctx, acc, payload_dangerous: bool):
    text_total = "\n".join(t for _, t in layers)
    m = None
    layer_m = "original"
    for layer, t in layers:
        m = INJECTION_PHRASES.search(t)
        if m:
            layer_m = layer
            break
    hidden = []
    for layer, t in layers:
        for mm in HIDDEN_HTML.finditer(t):
            content = (mm.group(1) or mm.group(2) or "").strip()
            if content and (IMPERATIVE_AGENT.search(content) or INJECTION_PHRASES.search(content)):
                hidden.append(content)
    tricks = [b for b in lec_flags if b in ("width_zero", "bidi", "unicode_tags", "homoglifos")]
    if ctx.channel == "DATA":
        if m or hidden:
            sev = S.CRITICAL if payload_dangerous else S.HIGH
            ev = m.group(0) if m else hidden[0]
            acc.add(Finding("INJECTION_PROMPT", "order_in_data", sev, ev, "KB-PRM-001", ctx.channel, layer_m,
                             "a fact tries to give orders to the agent"))
        elif payload_dangerous and IMPERATIVE_AGENT.search(text_total):
            acc.add(Finding("INJECTION_PROMPT", "load_dangerous_in_data", S.HIGH, "imperative + dangerous load in the document",
                             "KB-PRM-001", ctx.channel, layer_m))
        if tricks:
            sev = S.HIGH if (m or hidden or payload_dangerous) else S.MEDIA
            acc.add(Finding("INJECTION_PROMPT", "unicode_hidden", sev, ",".join(tricks), "KB-PRM-002" if sev <= S.MEDIA else "KB-PRM-001",
                             ctx.channel, "original", "invisible characters or homoglyphs in the data"))
        if "base64" in lec_flags and any(INJECTION_PHRASES.search(t) or IMPERATIVE_AGENT.search(t) for c, t in layers if c.startswith("base64")) and (m or payload_dangerous):
            acc.add(Finding("INJECTION_PROMPT", "order_encoded", S.HIGH, "base64", "KB-PRM-001", ctx.channel, "base64"))
    else:
        if m and not ctx.explanation:
            acc.add(Finding("INJECTION_PROMPT", "jailbreak_in_request", S.HIGH, m.group(0), "KB-PRM-001", ctx.channel, layer_m,
                             "the request tries to override the rules of the agent"))
        if tricks and (m or payload_dangerous):
            acc.add(Finding("OFUSCACION", "unicode_hidden", S.HIGH, ",".join(tricks), "KB-PRM-002" if not m else "KB-PRM-001", ctx.channel, "original"))
        elif tricks and "homoglifos" in tricks:
            acc.add(Finding("OFUSCACION", "homoglifos", S.MEDIA, ",".join(tricks), None, ctx.channel, "original",
                             "text with homoglyphs: I don't know why it comes like this"))


def detect(reading: Reading, ctx: Context, readings_sensitive_session: list) -> list[Finding]:
    """Run all detectors over all layers."""
    from .commands import analyze as _analyze_commands
    from .rules_v11 import apply as _rules_v11
    acc = _Accumulator()
    layers = reading.texts()
    layers = layers + [(c + "+log4j", _log4j_normalize(t)) for c, t in layers if "${" in t]
    new_readings: list = []
    _rules_table(layers, ctx, acc)
    _persistence(layers, ctx, acc)
    _sensitive_and_secrets(layers, ctx, acc, new_readings)
    for layer, t in layers:
        for h in _analyze_commands(t, ctx.channel, layer, ctx.domains_trusted, bool(readings_sensitive_session)):
            if ctx.explanation and ctx.channel == "INTENT":
                _degrade(h, "mención en pregunta o explicación")
            acc.add(h)
        for h in _rules_v11(t, ctx.channel, layer, ctx.explanation):
            acc.add(h)
    _red(layers, ctx, acc, there_is_reading_sensitive=bool(new_readings) or any(h.category == "THEFT_CREDENTIALS" and h.severity >= S.MEDIA for h in acc.findings))
    _web(layers, ctx, acc)
    payload = any(h.severity >= S.HIGH or (h.category == "THEFT_CREDENTIALS" and h.severity >= S.MEDIA)
                  for h in acc.findings if h.category not in ("INJECTION_PROMPT", "OFUSCACION"))
    _injection_prompt(layers, reading.flag_list, ctx, acc, payload)
    # Ocuscation + something dangerous: hiding is already evidence of intent.
    obfuscated = [b for b in reading.flag_list if b in ("base64", "hex", "url_encoding", "tricks_shell")]
    if obfuscated and any(h.layer != "original" and h.layer != "normalized" and h.severity >= S.HIGH for h in acc.findings) or \
       ("tricks_shell" in reading.flag_list and any(h.severity >= S.HIGH for h in acc.findings)):
        acc.add(Finding("OFUSCACION", "load_obfuscated", S.HIGH, ",".join(obfuscated), "KB-PRM-002", ctx.channel, "original",
                         "The dangerous cargo was hidden."))
    if ctx.channel == "DATA":
        # A log or report containing an attack doesn't attack the agent.
        # if the data tries to give commands (INJECTION_PROMPT); the rest is as a note.
        for h in acc.findings:
            if h.category != "INJECTION_PROMPT":
                h.severity = min(h.severity, S.LOW)
                h.note = (h.note + "; " if h.note else "") + "carga presente en el dato, sin orden al agente"
    else:
        readings_sensitive_session.extend(new_readings)
    return acc.findings
