import sys

import pytest

from thrasher import cli


def run_cli(monkeypatch, argv, prompts=()):
    monkeypatch.setattr(sys, "argv", ["thrasher", *argv])
    answers = iter(prompts)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt="Password: ": next(answers))
    cli.main()


def test_encrypt_decrypt_roundtrip(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"hello world")
    run_cli(monkeypatch, [str(src)], ["pw", "pw"])
    enc = tmp_path / "secret.txt.thrash"
    assert enc.exists()
    run_cli(monkeypatch, [str(enc)], ["pw"])
    assert (tmp_path / "secret.txt").read_bytes() == b"hello world"


def test_overwrite_rejected_on_encrypt(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"x")
    monkeypatch.setattr(sys, "argv", ["thrasher", "-w", str(src)])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 1
    assert not (tmp_path / "secret.txt.thrash").exists()


def test_empty_password_rejected(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"x")
    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, [str(src)], ["", ""])
    assert e.value.code == 1
