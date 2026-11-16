import os
import tarfile
import pytest
from deploy.rules_pruner import prune_rules, is_safe_tar_member


def test_is_safe_tar_member():
    m_ok = tarfile.TarInfo(name="rules/emerging-exploit.rules")
    assert is_safe_tar_member(m_ok) is True

    m_bad1 = tarfile.TarInfo(name="../etc/passwd")
    assert is_safe_tar_member(m_bad1) is False

    m_bad2 = tarfile.TarInfo(name="/etc/shadow")
    assert is_safe_tar_member(m_bad2) is False


def test_rules_pruner_filtering(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    exploit_file = rules_dir / "emerging-exploit.rules"
    exploit_file.write_text(
        '# Some comment\n'
        'alert tcp any any -> $HOME_NET 80 (msg:"ET EXPLOIT Apache Path Traversal"; sid:2001; rev:1;)\n'
        'alert tcp any any -> $HOME_NET 443 (msg:"ET EXPLOIT OpenSSL Overflow"; sid:2002; rev:1;)\n',
        encoding="utf-8"
    )

    scada_file = rules_dir / "emerging-scada.rules"
    scada_file.write_text(
        'alert tcp any any -> $HOME_NET 502 (msg:"ET SCADA Modbus Read"; sid:2003; rev:1;)\n',
        encoding="utf-8"
    )

    output_file = tmp_path / "trimmed.rules"
    stats = prune_rules(str(rules_dir), str(output_file), max_rules=100)

    assert stats["enabled_rules_selected"] == 2
    assert "emerging-exploit" in stats["categories"]
    assert "emerging-scada" not in stats["categories"]

    content = output_file.read_text(encoding="utf-8")
    assert "ET EXPLOIT Apache Path Traversal" in content
    assert "ET SCADA Modbus Read" not in content
