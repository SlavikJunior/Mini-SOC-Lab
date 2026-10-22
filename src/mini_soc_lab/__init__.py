"""Mini SOC Lab — учебный детекционный анализатор Windows/Linux/Web событий.

Все данные синтетические. Анализатор демонстрирует практики детектирования
и первичного триажа: эвристики, MITRE ATT&CK маппинг, severity, отчёты.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mini-soc-lab")
except PackageNotFoundError:  # запуски без установки пакета
    __version__ = "0.0.0-dev"

__all__ = ["__version__"]
