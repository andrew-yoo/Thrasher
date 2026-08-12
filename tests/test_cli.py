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
    run_cli(monkeypatch, ["-w", str(enc)], ["pw"])
    assert (tmp_path / "secret.txt").read_bytes() == b"hello world"


def test_encrypt_refuses_existing_output(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"x")
    run_cli(monkeypatch, [str(src)], ["pw", "pw"])
    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, [str(src)], ["pw", "pw"])
    assert e.value.code == 1


def test_encrypt_overwrites_with_flag(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"x")
    run_cli(monkeypatch, [str(src)], ["pw", "pw"])
    run_cli(monkeypatch, ["-w", str(src)], ["pw", "pw"])
    assert (tmp_path / "secret.txt.thrash").exists()


def test_decrypt_refuses_existing_output(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"x")
    run_cli(monkeypatch, [str(src)], ["pw", "pw"])
    enc = tmp_path / "secret.txt.thrash"
    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, [str(enc)], ["pw"])
    assert e.value.code == 1


def test_empty_password_rejected(tmp_path, monkeypatch):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"x")
    with pytest.raises(SystemExit) as e:
        run_cli(monkeypatch, [str(src)], ["", ""])
    assert e.value.code == 1
