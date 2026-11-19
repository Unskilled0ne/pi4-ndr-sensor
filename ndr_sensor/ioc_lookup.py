import os
import logging
from typing import Set, Optional

logger = logging.getLogger("ndr_sensor.ioc_lookup")

DEFAULT_IOC_PATH = "/var/lib/pi4-ndr/ioc_blocklist.txt"


class IOCBlocklist:
    """In-memory set of known-bad IPs and domains loaded from a text file."""

    def __init__(self, path: str = DEFAULT_IOC_PATH):
        self.path = path
        self._entries: Set[str] = set()
        self._mtime: float = 0.0
        self.reload()

    def reload(self) -> None:
        """Reload the blocklist from disk if the file has been modified."""
        if not os.path.isfile(self.path):
            return
        try:
            current_mtime = os.path.getmtime(self.path)
            if current_mtime == self._mtime:
                return
            with open(self.path, "r", encoding="utf-8") as f:
                entries = set()
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line.lower())
            self._entries = entries
            self._mtime = current_mtime
            logger.info("Loaded %d IOC entries from %s", len(self._entries), self.path)
        except Exception as e:
            logger.warning("Failed to load IOC blocklist: %s", e)

    def check(self, value: Optional[str]) -> bool:
        """Check if a value (IP or domain) is in the blocklist."""
        if not value:
            return False
        return value.strip().lower() in self._entries
