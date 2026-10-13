import subprocess
import sys
from pathlib import Path

from auth_log_parser import parse_failed_logins


SAMPLE_LOG = """
Mar 13 07:41:01 server sshd[1842]: Failed password for invalid user test from 203.0.113.10 port 51432 ssh2
Mar 13 07:41:12 server sshd[1845]: Failed password for root from 203.0.113.10 port 51439 ssh2
Mar 13 07:41:45 server sshd[1847]: Failed password for admin from 198.51.100.9 port 3333 ssh2
Mar 13 07:42:11 server sshd[1850]: Accepted password for josh from 192.0.2.10 port 54421 ssh2
Mar 13 07:42:30 server sshd[1851]: Failed password for invalid user oracle from 198.51.100.9 port 3352 ssh2
Mar 13 07:43:00 server sshd[1853]: Failed password for root from 203.0.113.10 port 51501 ssh2
"""


def test_parse_failed_logins_counts_users_and_ips():
    user_counts, ip_counts, total = parse_failed_logins(SAMPLE_LOG)

    assert total == 5
    assert user_counts["root"] == 2
    assert user_counts["test"] == 1
    assert user_counts["admin"] == 1
    assert user_counts["oracle"] == 1
    assert ip_counts["203.0.113.10"] == 3
    assert ip_counts["198.51.100.9"] == 2


def test_parse_failed_logins_ignores_successful_and_unrelated_lines():
    log_text = """
    Mar 13 server sshd[1]: Accepted password for josh from 192.0.2.10 port 54421 ssh2
    Mar 13 server sudo: pam_unix(sudo:session): session opened for user root
    Mar 13 server sshd[2]: Failed password for admin from 198.51.100.9 port 3333 ssh2
    """

    user_counts, ip_counts, total = parse_failed_logins(log_text)

    assert total == 1
    assert user_counts == {"admin": 1}
    assert ip_counts == {"198.51.100.9": 1}


def test_cli_prints_sample_summary():
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            str(repo_root / "auth_log_parser.py"),
            "--log",
            str(repo_root / "sample_auth.log"),
            "--top",
            "2",
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "Total failed login attempts: 5" in result.stdout
    assert "  - root: 2" in result.stdout
    assert "  - 203.0.113.10: 3" in result.stdout


def test_cli_missing_log_file_fails_cleanly(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    missing_log = tmp_path / "missing-auth.log"

    result = subprocess.run(
        [sys.executable, str(repo_root / "auth_log_parser.py"), "--log", str(missing_log)],
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert f"Log file not found: {missing_log}" in result.stderr
