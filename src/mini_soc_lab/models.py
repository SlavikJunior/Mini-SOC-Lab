"""Общие модели находок и утилиты для детекторов."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class MitreRef:
    """Ссылка на технику MITRE ATT&CK."""

    technique_id: str
    name: str
    tactic: str

    def to_dict(self) -> dict[str, str]:
        return {"technique_id": self.technique_id, "name": self.name, "tactic": self.tactic}

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


@dataclass(frozen=True)
class Finding:
    """Единая находка детектора независимо от источника логов."""

    source: str  # windows | web | linux
    kind: str  # машиночитаемый тип детекции
    severity: str
    evidence: str  # краткое человеческое обоснование
    mitre: tuple[MitreRef, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def mitre_primary(self) -> MitreRef | None:
        return self.mitre[0] if self.mitre else None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source": self.source,
            "type": self.kind,
            "severity": self.severity,
            "mitre": [ref.to_dict() for ref in self.mitre],
            "evidence": self.evidence,
        }
        if self.first_seen:
            data["first_seen"] = self.first_seen
        if self.last_seen:
            data["last_seen"] = self.last_seen
        data.update(self.details)
        return data


def any_of(event: dict[str, Any], *keys: str) -> str:
    """Собрать объединённую строку из полей события (для паттернов)."""
    parts = [str(event.get(key, "")) for key in keys]
    return " ".join(part.lower() for part in parts if part)
