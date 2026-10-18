"""Protocol catalogue, default service ports, and named bundles."""

# nxc-handled protocols — exactly what NetExec 1.5.x exposes as subcommands:
#   nxc {ssh,smb,wmi,winrm,ftp,rdp,vnc,ldap,mssql,nfs}
NXC_PROTOCOLS = ["smb", "ldap", "winrm", "ssh", "ftp", "mssql", "rdp", "wmi", "vnc", "nfs"]

# native Python sprayers (see runners.py)
NATIVE_PROTOCOLS = ["smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "mysql"]

ALL_PROTOCOLS = NXC_PROTOCOLS + NATIVE_PROTOCOLS

# Default service port(s) per protocol — reference for --list-protocols and docs.
PORTS = {
    "smb": "445", "ldap": "389/636", "winrm": "5985/5986", "ssh": "22",
    "ftp": "21", "mssql": "1433", "rdp": "3389", "wmi": "135", "vnc": "5900",
    "nfs": "2049",
    "smtp": "25/587", "smtps": "465", "imap": "143", "imaps": "993",
    "pop3": "110", "pop3s": "995", "mysql": "3306",
}

# One-line service description per protocol.
SERVICES = {
    "smb": "Windows file sharing / auth", "ldap": "Directory / Active Directory",
    "winrm": "Windows Remote Management", "ssh": "Secure Shell",
    "ftp": "File Transfer Protocol", "mssql": "Microsoft SQL Server",
    "rdp": "Remote Desktop", "wmi": "Windows Management Instrumentation",
    "vnc": "Virtual Network Computing", "nfs": "Network File System",
    "smtp": "Mail submission", "smtps": "Mail submission (TLS)",
    "imap": "Mailbox access", "imaps": "Mailbox access (TLS)",
    "pop3": "Mail retrieval", "pop3s": "Mail retrieval (TLS)",
    "mysql": "MySQL / MariaDB",
}

# named protocol bundles — expanded during argument parsing
BUNDLES = {
    "all":    ALL_PROTOCOLS,
    "ad":     ["smb", "ldap", "winrm", "wmi", "mssql", "rdp"],
    "mail":   ["smtp", "smtps", "imap", "imaps", "pop3", "pop3s"],
    "db":     ["mssql", "mysql"],
    "remote": ["ssh", "rdp", "winrm", "vnc"],
}


def expand_bundles(requested):
    """Expand bundle names, de-duplicate, and preserve order.
    Returns (protocols, unknown)."""
    protocols = []
    for name in requested:
        protocols.extend(BUNDLES.get(name, [name]))
    protocols = list(dict.fromkeys(protocols))
    unknown = [p for p in protocols if p not in ALL_PROTOCOLS]
    return protocols, unknown
