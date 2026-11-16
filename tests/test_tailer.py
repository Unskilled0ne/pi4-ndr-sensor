import os
import stat
import json
import pytest
from ndr_sensor.tailer import StateTracker, FileTailer


def test_state_tracker(tmp_path):
    state_file = tmp_path / "offset_state.json"
    tracker = StateTracker(str(state_file))

    assert tracker.get_offset("/var/log/test.log", 12345) == 0

    tracker.set_offset("/var/log/test.log", 12345, 1024)
    tracker.save()

    mode = stat.S_IMODE(os.stat(str(state_file)).st_mode)
    assert mode == 0o600

    tracker2 = StateTracker(str(state_file))
    assert tracker2.get_offset("/var/log/test.log", 12345) == 1024
    assert tracker2.get_offset("/var/log/test.log", 99999) == 0


def test_file_tailer_incremental_read(tmp_path):
    log_file = tmp_path / "test_eve.json"
    log_file.write_text("line1\nline2\n", encoding="utf-8")

    state_file = tmp_path / "state.json"
    tracker = StateTracker(str(state_file))
    tailer = FileTailer(str(log_file), tracker)

    lines = list(tailer.read_new_lines())
    assert lines == ["line1\n", "line2\n"]

    lines2 = list(tailer.read_new_lines())
    assert lines2 == []

    with open(log_file, "a", encoding="utf-8") as f:
        f.write("line3\n")

    lines3 = list(tailer.read_new_lines())
    assert lines3 == ["line3\n"]


def test_file_tailer_truncation_detection(tmp_path):
    log_file = tmp_path / "test_trunc.json"
    log_file.write_text("initial large log content line 1\nline 2\nline 3\n", encoding="utf-8")

    tailer = FileTailer(str(log_file))
    _ = list(tailer.read_new_lines())
    assert tailer.current_offset > 0

    log_file.write_text("restarted\n", encoding="utf-8")

    new_lines = list(tailer.read_new_lines())
    assert new_lines == ["restarted\n"]
