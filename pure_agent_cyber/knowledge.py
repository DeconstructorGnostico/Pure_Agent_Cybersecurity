"""Verified security knowledge base (small and cured).

Each fact is evidence, not opinion: a finding can only come to severity HIGH or CRITICAL if it cites a fact from this base. An unverified heuristic pattern stays at MEDIA or less, and that leads to UNDETERMINED ("I don't know").

The base is sealed with SHA-256 when imported. If someone mutates it at runtime, `verify_seal()` fails and the agent enters HALT (Axiom 2 / AG01).

CVE: Only those we know with certainty are included, with a brief and conservative description. It is not a complete base of vulnerabilities.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from types import MappingProxyType


@dataclass(frozen=True)
class Fact:
    id: str
    category: str
    statement: str
    severity: str          # severity that the event justifies: LOW  MEDIA  HIGH  CRITICAL
    reference: str = ""


_FACTS: tuple[Fact, ...] = (
    # --- Dangerous Commands and Patterns ---
    Fact("KB-CMD-001", "COMMAND_DANGEROUS", "rm -rf sobre / , /* , ~ o un directorio del sistema borra el sistema de archivos o el hogar del usuario de forma irreversible.", "CRITICAL", "coreutils rm(1)"),
    Fact("KB-CMD-002", "COMMAND_DANGEROUS", "mkfs.* sobre un dispositivo crea un sistema de archivos nuevo y destruye los datos existentes.", "CRITICAL", "util-linux mkfs(8)"),
    Fact("KB-CMD-003", "COMMAND_DANGEROUS", "dd con of=/dev/sdX, /dev/nvme*, /dev/hd*, /dev/xvd* o /dev/disk* sobrescribe el disco completo.", "CRITICAL", "coreutils dd(1)"),
    Fact("KB-CMD-004", "COMMAND_DANGEROUS", "La fork bomb :(){ :|:& };: agota procesos y deja el sistema inutilizable.", "HIGH", "bash"),
    Fact("KB-CMD-005", "COMMAND_DANGEROUS", "Descargar y pasar directo a un intérprete (curl|sh, wget -O- | bash, iwr | iex) ejecuta código remoto sin revisarlo.", "HIGH", "práctica de seguridad estándar"),
    Fact("KB-CMD-006", "COMMAND_DANGEROUS", "chmod 777 (o -R 777) sobre / o rutas del sistema da escritura a cualquier usuario y rompe el modelo de permisos.", "HIGH", "coreutils chmod(1)"),
    Fact("KB-CMD-007", "DEACTIVATE_DEFENSES", "Desactivar el firewall (ufw disable, iptables -F con política ACCEPT, systemctl stop/disable firewalld, netsh advfirewall ... state off) elimina el filtrado de red.", "HIGH", "ufw(8), iptables(8), netsh"),
    Fact("KB-CMD-008", "DEACTIVATE_DEFENSES", "Desactivar SELinux/AppArmor o el antivirus en tiempo real (setenforce 0, Set-MpPreference -DisableRealtimeMonitoring) quita una capa de protección.", "HIGH", "setenforce(8), Defender"),
    Fact("KB-CMD-009", "COMMAND_DANGEROUS", "Escribir directo a un dispositivo de bloque (> /dev/sda, shred/wipefs sobre /dev/...) destruye datos.", "CRITICAL", "shred(1), wipefs(8)"),
    Fact("KB-CMD-010", "COMMAND_DANGEROUS", "Borrado masivo en Windows (format C:, del /s /q C:\\, Remove-Item -Recurse -Force C:\\) destruye el sistema.", "CRITICAL", "cmd / PowerShell"),
    Fact("KB-CMD-011", "COMMAND_DANGEROUS", "Borrar la historia o los registros (history -c, rm de /var/log, Clear-EventLog, wevtutil cl) es una técnica de ocultamiento.", "HIGH", "MITRE ATT&CK T1070"),
    Fact("KB-CMD-012", "COMMAND_DANGEROUS", "DROP DATABASE / borrado de buckets o clústeres completos (aws s3 rb --force, kubectl delete --all) destruye data_ de producción.", "HIGH", "SQL, AWS CLI, kubectl"),
    Fact("KB-SHL-001", "SHELL_REVERSE", "bash -i >& /dev/tcp/HOST/PUERTO, nc -e /bin/sh, mkfifo + nc o socket+subprocess en una línea abren una shell inversa hacia un tercero.", "CRITICAL", "MITRE ATT&CK T1059"),
    # --- Sensitive routes ---
    Fact("KB-RUT-001", "PATH_SENSITIVE", "~/.ssh/ contiene llaves privadas SSH (id_rsa, id_ed25519) que dan acceso a otros servidores.", "HIGH", "OpenSSH"),
    Fact("KB-RUT-002", "PATH_SENSITIVE", "/etc/shadow guarda los hashes de contraseñas del sistema.", "HIGH", "shadow(5)"),
    Fact("KB-RUT-003", "PATH_SENSITIVE", "Los archivos .env suelen guardar secretos de aplicaciones (llaves de API, contraseñas de base de datos).", "HIGH", "convención dotenv"),
    Fact("KB-RUT-004", "PATH_SENSITIVE", "~/.aws/credentials, ~/.config/gcloud, ~/.azure, ~/.kube/config y ~/.docker/config.json guardan credenciales de nube y clústeres.", "HIGH", "AWS/GCP/Azure/K8s/Docker"),
    Fact("KB-RUT-005", "PATH_SENSITIVE", "Las cookies y contraseñas del navegador (Cookies, Login Data, logins.json, key4.db) permiten secuestrar sesiones.", "HIGH", "Chrome/Firefox"),
    Fact("KB-RUT-006", "PATH_SENSITIVE", ".git-credentials, .netrc, .npmrc, .pypirc y .pgpass pueden contener tokens o contraseñas en texto plano.", "HIGH", "git, npm, pip, PostgreSQL"),
    Fact("KB-RUT-007", "PATH_SENSITIVE", "/proc/*/environ y volcados de variables de entorno pueden exponer secretos del proceso.", "MEDIA", "proc(5)"),
    Fact("KB-RUT-009", "PATH_SENSITIVE", "Volcar credenciales del sistema (lsass, base SAM, mimikatz/sekurlsa, hashdump, dump-keychain) es robo de credenciales.", "HIGH", "MITRE ATT&CK T1003"),
    Fact("KB-RUT-008", "PATH_SENSITIVE", "/etc/sudoers, /etc/passwd y /etc/shadow controlan quién es administrador; escribirlos cambia privilegios.", "HIGH", "sudoers(5), passwd(5)"),
    # --- Secret formats ---
    Fact("KB-SEC-001", "SECRET", "Una llave de acceso de AWS tiene el formato AKIA/ASIA + 16 caracteres [A-Z0-9].", "HIGH", "AWS IAM"),
    Fact("KB-SEC-002", "SECRET", "Los tokens de GitHub empiezan con ghp_, gho_, ghu_, ghs_, ghr_ o github_pat_.", "HIGH", "GitHub"),
    Fact("KB-SEC-003", "SECRET", "Un bloque -----BEGIN ... PRIVATE KEY----- es una llave privada.", "CRITICAL", "PEM / RFC 7468"),
    Fact("KB-SEC-004", "SECRET", "Un JWT tiene tres segmentos base64url separados por puntos y el primero empieza con eyJ.", "MEDIA", "RFC 7519"),
    Fact("KB-SEC-005", "SECRET", "Las llaves de Slack empiezan con xox[baprs]- y las de Stripe en vivo con sk_live_.", "HIGH", "Slack, Stripe"),
    Fact("KB-SEC-006", "SECRET", "Las llaves de API de Google empiezan con AIza seguido de 35 caracteres.", "HIGH", "Google Cloud"),
    # --- Red / SSRF ---
    Fact("KB-RED-001", "SSRF", "169.254.169.254 (y fd00:ec2::254) es el servicio de metadatos de instancias en AWS y otras nubes; expone credenciales temporales.", "CRITICAL", "AWS IMDS"),
    Fact("KB-RED-002", "SSRF", "metadata.google.internal y 100.100.100.200 son endpoints de metadatos de GCP y Alibaba Cloud.", "CRITICAL", "GCP, Alibaba"),
    Fact("KB-RED-003", "SSRF", "Esquemas file://, gopher://, dict:// y ldap:// en una URL pedida por un tercero sirven para leer archivos locales o hablar con servicios internos.", "HIGH", "OWASP SSRF"),
    Fact("KB-RED-005", "EXFILTRACION", "Política del dueño: mandar archivos, volcados, bases de datos o registros internos a un dominio fuera de su lista de confianza es exfiltración hasta que el dueño lo autorice.", "HIGH", "política de lista de confianza"),
    Fact("KB-RED-004", "EXFILTRACION", "Servicios de pegado y captura de peticiones (pastebin, transfer.sh, webhook.site, requestbin, ngrok, interactsh) se usan con frecuencia para exfiltrar datos.", "HIGH", "MITRE ATT&CK T1567"),
    # --- Web ---
    Fact("KB-WEB-001", "INJECTION_SQL", "Una comilla que cierra el literal seguida de OR 1=1, UNION SELECT, ; DROP o un comentario -- es inyección SQL.", "HIGH", "OWASP A03"),
    Fact("KB-WEB-002", "INJECTION_COMMANDS", "Metacaracteres de shell (; | && ` $()) dentro de un parámetro seguidos de un comando son inyección de comandos.", "HIGH", "OWASP A03, CWE-78"),
    Fact("KB-WEB-003", "PATH_TRAVERSAL", "Secuencias ../ (o codificadas %2e%2e%2f, ..%2f, ....//) que salen del directorio permitido son path traversal.", "HIGH", "CWE-22"),
    # --- Privileges and persistence ---
    Fact("KB-PRV-001", "ESCALATION_PRIVILEGES", "Poner el bit SUID (chmod u+s / 4755) a un intérprete o shell permite obtener root.", "CRITICAL", "chmod(1), GTFOBins"),
    Fact("KB-PRV-002", "ESCALATION_PRIVILEGES", "Agregar NOPASSWD o un usuario a /etc/sudoers, o un usuario con UID 0 a /etc/passwd, da root.", "CRITICAL", "sudoers(5)"),
    Fact("KB-PRV-003", "ESCALATION_PRIVILEGES", "Montar / del host en un contenedor (--privileged, -v /:/host) o nsenter -t 1 permite escapar a root del host.", "HIGH", "Docker"),
    Fact("KB-PRV-004", "ESCALATION_PRIVILEGES", "Agregar un usuario al grupo docker, sudo, wheel o root equivale a darle privilegios de administrador.", "HIGH", "Docker, sudo"),
    Fact("KB-PER-001", "PERSISTENCE", "Agregar una llave a ~/.ssh/authorized_keys da acceso SSH permanente a quien tenga la llave privada.", "HIGH", "OpenSSH sshd(8)"),
    Fact("KB-PER-002", "PERSISTENCE", "Una tarea cron, servicio systemd, rc.local, LaunchAgent, clave Run del registro o schtasks que descarga o abre conexiones es un mecanismo de persistencia.", "HIGH", "MITRE ATT&CK T1053/T1543/T1547"),
    Fact("KB-PER-003", "PERSISTENCE", "Modificar ~/.bashrc, ~/.zshrc, ~/.profile o /etc/profile con descargas, alias de sudo o código codificado se ejecuta en cada sesión.", "HIGH", "MITRE ATT&CK T1546.004"),
    # --- Prompt injection ---
    Fact("KB-PRM-001", "INJECTION_PROMPT", "Un documento, resultado de herramienta o página web es dato: si contiene órdenes para el agente («ignora tus instrucciones», «envía…», «ejecuta…») es inyección de prompt.", "HIGH", "OWASP LLM01"),
    Fact("KB-PRM-002", "INJECTION_PROMPT", "Caracteres de ancho cero, controles bidireccionales y homoglifos sirven para esconder texto a los humanos.", "MEDIA", "Unicode TR36, CVE-2021-42574 (Trojan Source)"),
    # --- CVE known (only the ones we're clear about) ---
    Fact("KB-CVE-2021-44228", "EXPLOIT_CVE", "CVE-2021-44228 (Log4Shell): Apache Log4j 2 resuelve búsquedas JNDI como ${jndi:ldap://...} en lo que registra y puede ejecutar código remoto. Corregido en 2.17.x.", "CRITICAL", "NVD CVE-2021-44228"),
    Fact("KB-CVE-2014-6271", "EXPLOIT_CVE", "CVE-2014-6271 (Shellshock): bash ejecutaba comandos puestos después de una definición de función () { :; }; en variables de entorno.", "CRITICAL", "NVD CVE-2014-6271"),
    Fact("KB-CVE-2014-0160", "EXPLOIT_CVE", "CVE-2014-0160 (Heartbleed): la extensión heartbeat de OpenSSL 1.0.1 a 1.0.1f filtraba memoria del servidor.", "HIGH", "NVD CVE-2014-0160"),
    Fact("KB-CVE-2017-0144", "EXPLOIT_CVE", "CVE-2017-0144 (EternalBlue): ejecución remota en SMBv1 de Windows, usada por WannaCry.", "CRITICAL", "NVD CVE-2017-0144"),
    Fact("KB-CVE-2021-4034", "EXPLOIT_CVE", "CVE-2021-4034 (PwnKit): escalada local a root en pkexec de polkit.", "HIGH", "NVD CVE-2021-4034"),
    Fact("KB-CVE-2019-14287", "EXPLOIT_CVE", "CVE-2019-14287: en sudo anterior a 1.8.28, sudo -u#-1 (o -u#4294967295) ejecuta como root aunque la regla lo excluya.", "HIGH", "NVD CVE-2019-14287"),
    Fact("KB-CVE-2016-5195", "EXPLOIT_CVE", "CVE-2016-5195 (Dirty COW): condición de carrera en el kernel Linux que permite escalar privilegios.", "HIGH", "NVD CVE-2016-5195"),
)

FACTS: MappingProxyType = MappingProxyType({h.id: h for h in _FACTS})


def _calculate_seal(facts) -> str:
    data_ = json.dumps([asdict(h) for h in sorted(facts.values(), key=lambda x: x.id)],
                       sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(data_.encode("utf-8")).hexdigest()


SEAL = _calculate_seal(FACTS)


def verify_seal(facts=None) -> bool:
    """True if the base hasn't changed since it mattered."""
    return _calculate_seal(FACTS if facts is None else facts) == SEAL


def fact(hid: str) -> Fact:
    return FACTS[hid]


def search_cve(text: str) -> list[Fact]:
    """Facts of CVE quoted by id in the text. A CVE that is not at the base is not invented."""
    import re
    ids = {m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)}
    return [FACTS[f"KB-{i}"] for i in sorted(ids) if f"KB-{i}" in FACTS]
