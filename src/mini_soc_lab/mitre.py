"""Маппинг техник MITRE ATT&CK, использованных в детекциях проекта."""
from __future__ import annotations

from mini_soc_lab.models import MitreRef

_T = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1204": ("User Execution", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1033": ("Account Discovery", "Discovery"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1485": ("Data Destruction", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1078.003": ("Local Accounts", "Defense Evasion"),
}


def ref(technique_id: str) -> MitreRef:
    """Построить MitreRef по идентификатору техники."""
    name, tactic = _T[technique_id]
    return MitreRef(technique_id=technique_id, name=name, tactic=tactic)


def coverage_table(finding_dicts: list[dict[str, object]]) -> list[dict[str, str]]:
    """Сгруппировать покрытия техник по находкам для отчёта."""
    seen: dict[str, tuple[str, str, int]] = {}
    for finding in finding_dicts:
        for technique in finding.get("mitre", []):  # type: ignore[attr-defined]
            tid = str(technique.get("technique_id"))
            if tid in seen:
                name, tactic, count = seen[tid]
                seen[tid] = (name, tactic, count + 1)
            else:
                seen[tid] = (
                    str(technique.get("name")),
                    str(technique.get("tactic")),
                    1,
                )
    return [
        {
            "technique_id": tid,
            "name": name,
            "tactic": tactic,
            "findings": str(count),
        }
        for tid, (name, tactic, count) in sorted(seen.items())
    ]
