import os
import json
import logging
from typing import Dict, Any, Optional, Generator

logger = logging.getLogger("ndr_sensor.tailer")
MAX_READ_LINES_PER_CYCLE = 5000


class StateTracker:
    def __init__(self, state_file_path: str):
        self.state_file_path = os.path.abspath(state_file_path)
        self._state: Dict[str, Dict[str, int]] = {}
        self.load()

    def load(self) -> None:
        if os.path.isfile(self.state_file_path):
            try:
                with open(self.state_file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._state = data
            except Exception as e:
                logger.warning("Could not read state file: %s", e)
                self._state = {}

    def save(self) -> None:
        try:
            parent = os.path.dirname(self.state_file_path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, mode=0o700, exist_ok=True)

            temp_file = f"{self.state_file_path}.tmp"
            fd = os.open(temp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
            os.replace(temp_file, self.state_file_path)
        except PermissionError:
            fallback = os.path.expanduser("~/.cache/pi4-ndr/offset_state.json")
            if self.state_file_path != fallback:
                self.state_file_path = fallback
                self.save()
        except Exception as e:
            logger.error("State save failed: %s", e)

    def get_offset(self, file_path: str, inode: int) -> int:
        norm_path = os.path.realpath(file_path)
        entry = self._state.get(norm_path, {})
        if entry.get("inode") == inode:
            return max(0, int(entry.get("offset", 0)))
        return 0

    def set_offset(self, file_path: str, inode: int, offset: int) -> None:
        norm_path = os.path.realpath(file_path)
        self._state[norm_path] = {"inode": inode, "offset": max(0, offset)}


class FileTailer:
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
        if not os.path.exists(self.file_path):
            return

        try:
            stat = os.stat(self.file_path)
        except OSError:
            return

        if self.current_inode is not None and stat.st_ino != self.current_inode:
            self.current_inode = stat.st_ino
            self.current_offset = 0
        elif stat.st_size < self.current_offset:
            self.current_offset = 0

        self.current_inode = stat.st_ino

        if stat.st_size == self.current_offset:
            return

        lines_read = 0
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.current_offset)
                while lines_read < MAX_READ_LINES_PER_CYCLE:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        f.seek(self.current_offset)
                        break
                    self.current_offset = f.tell()
                    lines_read += 1
                    yield line

            if self.state_tracker and self.current_inode:
                self.state_tracker.set_offset(self.file_path, self.current_inode, self.current_offset)
        except OSError as e:
            logger.error("Read failure on %s: %s", self.file_path, e)
