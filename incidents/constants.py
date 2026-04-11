from __future__ import annotations

from .models import Incident

MITRE_TACTICS = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0040", "name": "Impact"},
]

MITRE_TECHNIQUES = [
    {"id": "T1566", "name": "Phishing"},
    {"id": "T1190", "name": "Exploit Public-Facing Application"},
    {"id": "T1078", "name": "Valid Accounts"},
    {"id": "T1059", "name": "Command and Scripting Interpreter"},
    {"id": "T1047", "name": "Windows Management Instrumentation"},
    {"id": "T1027", "name": "Obfuscated/Compressed Files"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
    {"id": "T1105", "name": "Ingress Tool Transfer"},
    {"id": "T1562", "name": "Impair Defenses"},
    {"id": "T1114", "name": "Email Collection"},
]

KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

ESCALATION_LEVELS = [
    {"id": "none", "label": "Nenhum"},
    {"id": "tier1", "label": "Tier 1"},
    {"id": "tier2", "label": "Tier 2"},
    {"id": "tier3", "label": "Tier 3"},
    {"id": "management", "label": "Gestao"},
]

DATA_CLASSIFICATIONS = [
    {"id": value, "label": label}
    for value, label in Incident.DataClassification.choices
]

SEVERITY_BY_RISK = [
    {"label": Incident.Severity.LOW, "range": "0-39"},
    {"label": Incident.Severity.MEDIUM, "range": "40-59"},
    {"label": Incident.Severity.HIGH, "range": "60-79"},
    {"label": Incident.Severity.CRITICAL, "range": "80-100"},
]
