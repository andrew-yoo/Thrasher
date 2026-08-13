import errno
import os
import pytest

from thrasher.fileio import atomic_write, read_chunks, read_exact


def test_read_chunks_full_and_partial(tmp_path):
    path = str(tmp_path / "test.bin")
    with open(path, "wb") as f:
        f.write(b"a" * 10)
    assert list(read_chunks(path, 4)) == [b"a" * 4, b"a" * 4, b"a" * 2]


def test_read_chunks_empty(tmp_path):
    path = str(tmp_path / "empty.bin")
    open(path, "wb").close()
    assert list(read_chunks(path, 4)) == []


def test_read_exact(tmp_path):
    path = str(tmp_path / "test.bin")
    with open(path, "wb") as f:
        f.write(b"0123456789")
    with open(path, "rb") as f:
        assert read_exact(f, 4) == b"0123"
        assert read_exact(f, 6) == b"456789"


def test_read_exact_short_raises(tmp_path):
    path = str(tmp_path / "test.bin")
    with open(path, "wb") as f:
        f.write(b"abc")
    with open(path, "rb") as f:
        with pytest.raises(EOFError):
            read_exact(f, 5)


def test_atomic_write_commits(tmp_path):
    target = str(tmp_path / "out.bin")
    with atomic_write(target) as f:
        f.write(b"data")
    assert os.path.exists(target)
    with open(target, "rb") as f:
        assert f.read() == b"data"


def test_atomic_write_no_overwrite_refuses_existing(tmp_path):
    target = str(tmp_path / "out.bin")
    with open(target, "wb") as f:
        f.write(b"original")
    with pytest.raises(FileExistsError):
        with atomic_write(target, overwrite=False) as f:
            f.write(b"replacement")
    assert open(target, "rb").read() == b"original"
    assert [p for p in os.listdir(tmp_path) if p.startswith(".thrasher-")] == []


def test_atomic_write_no_overwrite_commits_when_absent(tmp_path):
    target = str(tmp_path / "out.bin")
    with atomic_write(target, overwrite=False) as f:
        f.write(b"data")
    assert open(target, "rb").read() == b"data"


def test_atomic_write_no_overwrite_cleans_on_error(tmp_path):
    target = str(tmp_path / "out.bin")
    with pytest.raises(RuntimeError):
        with atomic_write(target, overwrite=False) as f:
            f.write(b"partial")
            raise RuntimeError("boom")
    assert not os.path.exists(target)


def test_atomic_write_no_overwrite_refuses_symlink(tmp_path):
    target = tmp_path / "out.bin"
    link = tmp_path / "alink"
    target.write_bytes(b"existing")
    os.symlink(target, link)
    with pytest.raises(FileExistsError):
        with atomic_write(str(link), overwrite=False) as f:
            f.write(b"data")
    assert os.path.islink(link)


def test_atomic_write_closes_file_on_fsync_failure(tmp_path, monkeypatch):
    target = str(tmp_path / "out.bin")

    def fail_fsync(fd):
        raise OSError("fsync failed")

    monkeypatch.setattr("thrasher.fileio.os.fsync", fail_fsync)
    aw = atomic_write(target)
    with pytest.raises(OSError):
        with aw:
            aw.file.write(b"data")
    assert aw.file.closed
    assert not os.path.exists(target)
    assert [p for p in os.listdir(tmp_path) if p.startswith(".thrasher-")] == []


def test_fsync_dir_propagates_open_error(tmp_path, monkeypatch):
    aw = atomic_write(str(tmp_path / "out.bin"))

    def fail_open(*a, **k):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("thrasher.fileio.os.open", fail_open)
    with pytest.raises(OSError) as e:
        aw._fsync_dir()
    assert e.value.errno == errno.EACCES


def test_fsync_dir_ignores_unsupported(tmp_path, monkeypatch):
    aw = atomic_write(str(tmp_path / "out.bin"))

    def unsupported(fd):
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr("thrasher.fileio.os.fsync", unsupported)
    aw._fsync_dir()  # must not raise


def test_fsync_dir_propagates_real_error(tmp_path, monkeypatch):
    aw = atomic_write(str(tmp_path / "out.bin"))

    def io_error(fd):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr("thrasher.fileio.os.fsync", io_error)
    with pytest.raises(OSError) as e:
        aw._fsync_dir()
    assert e.value.errno == errno.EIO


def test_atomic_write_cleans_on_replace_failure(tmp_path, monkeypatch):
    target = str(tmp_path / "out.bin")

    def boom(src, dst):
        raise OSError("nope")

    monkeypatch.setattr("thrasher.fileio.os.replace", boom)
    with pytest.raises(OSError):
        with atomic_write(target) as f:
            f.write(b"data")
    assert [p for p in os.listdir(tmp_path) if p.startswith(".thrasher-")] == []


def test_atomic_write_cleans_on_error(tmp_path):
    target = str(tmp_path / "out.bin")
    with pytest.raises(RuntimeError):
        with atomic_write(target) as f:
            f.write(b"partial")
            raise RuntimeError("boom")
    assert not os.path.exists(target)
    assert [p for p in os.listdir(tmp_path) if p.startswith(".thrasher-")] == []
