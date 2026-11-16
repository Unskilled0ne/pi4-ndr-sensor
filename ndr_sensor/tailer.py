import os
import json
import logging
from typing import Dict, Any, Optional, Generator

logger = logging.getLogger("ndr_sensor.tailer")


class StateTracker:
    """
    Persists file offsets and inode numbers across daemon restarts
    to prevent duplicate alerts and missing records during downtime.
    """

    def __init__(self, state_file_path: str):
        self.state_file_path = state_file_path
        self._state: Dict[str, Dict[str, int]] = {}
        self.load()

    def load(self) -> None:
        if os.path.exists(self.state_file_path):
            try:
                with open(self.state_file_path, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
            except Exception as e:
                logger.warning("Failed to load state file %s: %s", self.state_file_path, e)
                self._state = {}

    def save(self) -> None:
        try:
            parent = os.path.dirname(self.state_file_path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            temp_file = f"{self.state_file_path}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
            os.replace(temp_file, self.state_file_path)
        except Exception as e:
            logger.error("Failed to save state file %s: %s", self.state_file_path, e)

    def get_offset(self, file_path: str, inode: int) -> int:
        entry = self._state.get(file_path, {})
        if entry.get("inode") == inode:
            return entry.get("offset", 0)
        return 0

    def set_offset(self, file_path: str, inode: int, offset: int) -> None:
        self._state[file_path] = {"inode": inode, "offset": offset}


class FileTailer:
    """
    Lightweight, rotation-aware file reader that yields new lines as they are written.
    """

    def __init__(self, file_path: str, state_tracker: Optional[StateTracker] = None, start_at_end: bool = False):
        self.file_path = file_path
        self.state_tracker = state_tracker
        self.current_inode: Optional[int] = None
        self.current_offset: int = 0
        self._init_position(start_at_end)

    def _init_position(self, start_at_end: bool) -> None:
        if not os.path.exists(self.file_path):
            return

        try:
            stat = os.stat(self.file_path)
            self.current_inode = stat.st_ino
            if self.state_tracker:
                self.current_offset = self.state_tracker.get_offset(self.file_path, self.current_inode)
            elif start_at_end:
                self.current_offset = stat.st_size
            else:
                self.current_offset = 0
        except OSError:
            pass

    def read_new_lines(self) -> Generator[str, None, None]:
        """Reads and yields all new lines since the last check."""
        if not os.path.exists(self.file_path):
            return

        try:
            stat = os.stat(self.file_path)
        except OSError:
            return

        # Check for log rotation: inode change or file truncation
        if self.current_inode is not None and stat.st_ino != self.current_inode:
            logger.info("Log rotation detected for %s (new inode)", self.file_path)
            self.current_inode = stat.st_ino
            self.current_offset = 0
        elif stat.st_size < self.current_offset:
            logger.info("Log truncation detected for %s", self.file_path)
            self.current_offset = 0

        self.current_inode = stat.st_ino

        if stat.st_size == self.current_offset:
            return

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.current_offset)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    # If line doesn't end with newline, we may have caught a partial write
                    if not line.endswith("\n"):
                        f.seek(self.current_offset)
                        break
                    self.current_offset = f.tell()
                    yield line

            if self.state_tracker and self.current_inode:
                self.state_tracker.set_offset(self.file_path, self.current_inode, self.current_offset)
        except OSError as e:
            logger.error("Error reading file %s: %s", self.file_path, e)
