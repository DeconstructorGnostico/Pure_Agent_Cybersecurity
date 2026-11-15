"""Structural command analysis (v1.1).

Regular expressions of `detectors.py` depend on the order of the flags. Here each line is broken into segments (;  ) respecting quotation marks, separate banners from arguments and reasoned by category:

- permissions that let everyone write about system routes (chmod 777 -R /etc ...);
- security services detained, disabled or masked with any option
  (systemctl mask --now firewalld, service ufw stop, Stop-Service WinDefend, sc config …);
- recursive deletion after `cd` to a system path (cd /var  rm -rf *);
- recursive deletion of a Windows root by pipe (Get-ChildItem C:★  Remove-Item -Recurse);
- archived or copyed secret folders (~/.ssh, ~/.gnupg, ~/.aws ...) sent by pipeline
  to a network client (ssh, nc, socat, openssl, curl);
- cloud destinations (s3://, gs://, remote rclone:) that are not on the owner list.

It does not execute anything. Returns findings with the verified fact that supports them.
"""
from __future__ import annotations

import re
import shlex
from typing import Optional

from .findings import Finding, Severity as S

I = re.IGNORECASE

PATHS_SYSTEM = ("/", "/etc", "/usr", "/var", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/home", "/root",
                 "/opt", "/srv", "/sys", "/dev", "/proc", "~", "$HOME", "${HOME}")

SERVICES_SECURITY = re.compile(
    r"^(?:firewalld|ufw|iptables|ip6tables|nftables|netfilter-persistent|apparmor|auditd|fail2ban|sshguard|"
    r"clamav[\w-]*|clamd|falcon-sensor|wazuh-agent|ossec|osqueryd|crowdstrike\w*|sentinel\w*|cbagentd|"
    r"mpssvc|windefend|wscsvc|securityhealthservice|sense|wdnissvc|bfe|eventlog|sysmon\w*|selinux)(?:\.service)?$", I)

CLIENTS_RED = re.compile(r"^(?:ssh|nc|ncat|netcat|socat|telnet|openssl|curl|wget|ftp|sftp|tftp|smbclient)$", I)
ARCHIVERS = re.compile(r"^(?:tar|zip|7z|7za|cpio|gzip|bzip2|xz|base64|xxd|cat|cp|rsync|scp|dd|find)$", I)

DIR_SECRETS = re.compile(
    r"(?:^|/|~)(?:\.ssh|\.gnupg|\.aws|\.kube|\.docker|\.azure|\.config/gcloud|\.password-store)/?$|"
    r"^/etc/ssl/private/?$|^/var/lib/jenkins/secrets|^/root/?$", I)


def _tokens(sec: str) -> list[str]:
    try:
        return shlex.split(sec, posix=True)
    except ValueError:
        return sec.split()


def segments(line: str) -> list[tuple[str, str]]:
    """[(separador_prior, text_of_segment)] respecting quotation marks."""
    out: list[tuple[str, str]] = []
    try:
        lx = shlex.shlex(line, posix=True, punctuation_chars=";&|")
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return [("", line)]
    sep, actual = "", []
    for tk in toks:
        if tk and set(tk) <= set(";&|"):
            if actual:
                out.append((sep, " ".join(actual)))
            sep, actual = tk, []
        else:
            actual.append(tk)
    if actual:
        out.append((sep, " ".join(actual)))
    return out


def _without_prefixes(toks: list[str]) -> list[str]:
    while toks and (toks[0] in ("sudo", "doas", "nohup", "time", "nice", "env", "exec", "command", "builtin")
                    or re.fullmatch(r"[A-Za-z_]\w*=\S*", toks[0]) or (toks[0].startswith("-") and len(toks) > 1)):
        toks = toks[1:]
    return toks


def _is_path_system(arg: str, cwd: Optional[str] = None) -> bool:
    a = arg.strip("'\"")
    if a in ("*", ".", "./*", "./", "*.*") and cwd:
        a = cwd
    a = re.sub(r"/\*+$", "", a) or "/"
    a = a.rstrip("/") or "/"
    if a in PATHS_SYSTEM:
        return True
    return any(a == r or a.startswith(r + "/") and a.count("/") <= 2 for r in ("/etc", "/usr", "/boot", "/bin", "/sbin", "/lib", "/root")) \
        and not a.startswith(("/usr/local/src", "/etc/nginx/sites", "/var/tmp"))


def _mode_escribible_by_all(m: str) -> bool:
    if re.fullmatch(r"0?[0-7]{3}", m):
        return m[-1] in "2367"
    if re.fullmatch(r"[0-7]{4}", m):
        return m[-1] in "2367" and m[0] != "1"   # 1777 (sticky, like /tmp) let go
    return bool(re.fullmatch(r"(?:[ugo]*a[ugo]*|[ugo]*o[ugo]*|)\+[rwxXst]*w[rwxXst]*", m)) or m in ("a+rwx", "ugo+rwx", "o+rwx")


def analyze(line: str, channel: str, layer: str, cloud_trusted: frozenset, reading_sensitive_prior: bool = False) -> list[Finding]:
    hs: list[Finding] = []
    segs = segments(line)
    cwd: Optional[str] = None
    secret_in_pipeline = False
    for i, (sep, sec) in enumerate(segs):
        toks = _without_prefixes(_tokens(sec))
        if not toks:
            continue
        cmd = toks[0].rsplit("/", 1)[-1].lower()
        args = toks[1:]
        flag_list = [a for a in args if a.startswith("-")]
        positional = [a for a in args if not a.startswith("-")]
        if cmd == "cd" and positional:
            cwd = positional[0]
            continue
        # 1. Writeable permissions by all on system routes
        if cmd == "chmod" and positional:
            mode, targets = positional[0], positional[1:]
            if _mode_escribible_by_all(mode) and any(_is_path_system(o, cwd) for o in targets):
                hs.append(Finding("COMMAND_DANGEROUS", "chmod_escribible_system", S.HIGH, sec, "KB-CMD-006", channel, layer))
        if cmd == "chown" and any(b in ("-R", "--recursive") for b in flag_list) and any(_is_path_system(o, cwd) for o in positional[1:]):
            hs.append(Finding("COMMAND_DANGEROUS", "chown_recursive_system", S.HIGH, sec, "KB-CMD-006", channel, layer))
        # 2. Security services turned off, with any option
        verb_turns_off = {"stop", "disable", "mask", "kill"}
        if cmd == "systemctl" and any(p.lower() in verb_turns_off for p in positional) and any(SERVICES_SECURITY.match(p) for p in positional):
            hs.append(Finding("COMMAND_DANGEROUS", "service_security_off", S.HIGH, sec, "KB-CMD-007", channel, layer))
        if cmd == "service" and len(positional) >= 2 and SERVICES_SECURITY.match(positional[0]) and positional[1].lower() in ("stop", "disable"):
            hs.append(Finding("COMMAND_DANGEROUS", "service_security_off", S.HIGH, sec, "KB-CMD-007", channel, layer))
        if cmd in ("update-rc.d", "chkconfig") and positional and SERVICES_SECURITY.match(positional[0]) and \
                any(p.lower() in ("disable", "remove", "off") for p in positional[1:]):
            hs.append(Finding("COMMAND_DANGEROUS", "service_security_off", S.HIGH, sec, "KB-CMD-007", channel, layer))
        if cmd in ("stop-service", "set-service") and any(SERVICES_SECURITY.match(p.strip("'\"")) for p in positional) and \
                (cmd == "stop-service" or re.search(r"-startuptype\s+disabled|-status\s+stopped", sec, I)):
            hs.append(Finding("COMMAND_DANGEROUS", "service_security_off", S.HIGH, sec, "KB-CMD-008", channel, layer))
        if cmd in ("sc", "sc.exe") and len(positional) >= 2 and positional[0].lower() in ("stop", "config", "delete") and \
                SERVICES_SECURITY.match(positional[1]) and (positional[0].lower() != "config" or re.search(r"start\s*=\s*disabled", sec, I)):
            hs.append(Finding("COMMAND_DANGEROUS", "service_security_off", S.HIGH, sec, "KB-CMD-008", channel, layer))
        # 3. Recursive deletion relative to a system path (cd /var rm -rf *)
        if cmd == "rm" and any(re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*|--recursive", b) for b in flag_list) and \
                any(_is_path_system(o, cwd) for o in positional):
            hs.append(Finding("COMMAND_DANGEROUS", "rm_recursive_system", S.CRITICAL, sec if not cwd else f"cd {cwd} … {sec}", "KB-CMD-001", channel, layer))
        # 5. Piped secrets to the net.
        if ARCHIVERS.match(cmd) and any(DIR_SECRETS.search(p.strip("'\"")) for p in positional):
            secret_in_pipeline = True
        if sep == "|" and CLIENTS_RED.match(cmd) and (secret_in_pipeline or reading_sensitive_prior):
            hs.append(Finding("THEFT_CREDENTIALS", "secrets_by_pipeline_a_red", S.CRITICAL, sec, "KB-RUT-001", channel, layer,
                               "a folder of secrets is packaged and sent by a network client"))
        # 6. Cloud Destinations off the Owner's List
        destination = None
        if cmd == "aws" and len(positional) >= 3 and positional[0] == "s3" and positional[1] in ("cp", "sync", "mv"):
            src, dst = positional[2], positional[-1]
            if not src.startswith("s3://") and dst.startswith("s3://"):
                destination = dst
        elif cmd in ("gsutil", "gcloud") and positional:
            gs = [p for p in positional if p.startswith("gs://")]
            local = [p for p in positional if not p.startswith("gs://") and p not in ("cp", "rsync", "mv", "storage")]
            if gs and local and positional.index(gs[-1]) > positional.index(local[-1]) and any(p in ("cp", "rsync", "mv") for p in positional):
                destination = gs[-1]
        elif cmd == "rclone" and len(positional) >= 3 and positional[0] in ("copy", "sync", "move", "copyto", "moveto"):
            dst = positional[-1]
            if re.match(r"^[\w.-]+:", dst) and not re.match(r"^[a-zA-Z]:\\", dst):
                destination = dst
        elif cmd == "azcopy" and len(positional) >= 3 and positional[0] in ("copy", "sync"):
            if positional[-1].startswith("https://") and not positional[1].startswith("https://"):
                destination = positional[-1]
        if destination:
            name_ = re.sub(r"^(?:s3|gs)://", "", destination).split("/")[0].split(":")[0].lower()
            name_ = re.sub(r"^https://([\w-]+)\.blob\.core\.windows\.net.*", r"\1", name_)
            if name_ not in cloud_trusted:
                hs.append(Finding("EXFILTRACION", "cloud_no_trusted", S.HIGH, f"{sec[:60]} → {destination}", "KB-RED-005", channel, layer,
                                   "copying data to a pocket or remote that is not in the owner's list"))
    # 4. Windows root deleted by pipe (look at raw line: shlex eats the )
    m = re.search(r"\b(?:get-childitem|gci|dir|ls)\s+['\"]?[a-z]:\\['\"]?(?:\s[^|\n]*)?\|\s*(?:remove-item|ri|del|rm|erase)\b[^\n]*-recurse", line, I)
    if m:
        hs.append(Finding("COMMAND_DANGEROUS", "deleted_root_windows", S.CRITICAL, m.group(0), "KB-CMD-010", channel, layer))
    # 5b. Secrets → network even if they come within printf/echo/comillas (layers hex/base64)
    m = re.search(
        r"(?:~|/root|/home/[\w.-]+)?/?\.ssh\b[^\n]{0,40}\|\s*(?:ssh|nc|ncat|netcat|socat|curl|openssl)\b|"
        r"(?:tar|zip|cpio|cat|base64)\b[^\n]{0,60}\.ssh\b[^\n]{0,40}\|\s*(?:ssh|nc|ncat|netcat|socat|curl)\b",
        line, I)
    if m:
        hs.append(Finding("THEFT_CREDENTIALS", "secrets_by_pipeline_a_red", S.CRITICAL, m.group(0), "KB-RUT-001", channel, layer,
                           "a folder of secrets is sent by a network client"))
    return hs
