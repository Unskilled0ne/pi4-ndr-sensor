import time
from collections import OrderedDict
from typing import Optional


class AlertDeduplicator:
    """Suppress duplicate alerts within a configurable time window."""

    def __init__(self, window_seconds: float = 60.0, max_entries: int = 10000):
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._suppressed_counts: dict[str, int] = {}

    def _make_key(self, signature: Optional[str], src_ip: Optional[str], dest_ip: Optional[str]) -> str:
        return f"{signature or ''}|{src_ip or ''}|{dest_ip or ''}"

    def is_duplicate(self, signature: Optional[str], src_ip: Optional[str], dest_ip: Optional[str]) -> bool:
        now = time.time()
        key = self._make_key(signature, src_ip, dest_ip)

        # Evict expired entries
        while self._seen:
            oldest_key, oldest_time = next(iter(self._seen.items()))
            if now - oldest_time > self.window_seconds:
                self._seen.pop(oldest_key)
                self._suppressed_counts.pop(oldest_key, None)
            else:
                break

        # Enforce max size
        while len(self._seen) >= self.max_entries:
            evicted_key, _ = self._seen.popitem(last=False)
            self._suppressed_counts.pop(evicted_key, None)

        if key in self._seen:
            self._suppressed_counts[key] = self._suppressed_counts.get(key, 0) + 1
            self._seen.move_to_end(key)
            return True

        self._seen[key] = now
        return False

    def get_suppressed_count(self, signature: Optional[str], src_ip: Optional[str], dest_ip: Optional[str]) -> int:
        key = self._make_key(signature, src_ip, dest_ip)
        return self._suppressed_counts.get(key, 0)
