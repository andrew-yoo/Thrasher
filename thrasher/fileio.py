import errno
import os
import sys
import tempfile

_FSYNC_UNSUPPORTED = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EBADF, errno.EROFS}


def read_chunks(path: str, size: int):
    with open(path, "rb") as f:
        while True:
            data = f.read(size)
            if not data:
                break
            yield data


def read_exact(f, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = f.read(size - len(data))
        if not chunk:
            raise EOFError("Unexpected end of file")
        data += chunk
    return data


class atomic_write:
    def __init__(self, path: str, overwrite: bool = True) -> None:
        self.path = os.path.abspath(path)
        self.overwrite = overwrite
        self.directory = os.path.dirname(self.path)
        self.created = None
        self.created_id = None
        self.committed = False
        if overwrite:
            fd, self.created = tempfile.mkstemp(prefix=".thrasher-", dir=self.directory)
        else:
            # Create-if-absent is atomic on every filesystem (no hard links needed),
            # but the file is written in place: a crash can leave a partial file at
            # a path that was previously absent, and readers may see partial output.
            # Never destroys pre-existing data, since creation is exclusive. After
            # such a crash the leftover file must be removed or overwritten with -w.
            # On Windows, st_dev/st_ino are only meaningful on NTFS; filesystems
            # without file-reference numbers (FAT/exFAT/WebDAV) report 0, so a
            # failed write leaves a partial file that must be removed or overwritten.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            self.created = self.path
            st = os.fstat(fd)
            self.created_id = (st.st_dev, st.st_ino)
        self.file = os.fdopen(fd, "wb")

    def __enter__(self):
        return self.file

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.file.flush()
                os.fsync(self.file.fileno())
                self.file.close()
                if self.overwrite:
                    os.replace(self.created, self.path)
                elif all(self.created_id):
                    try:
                        st = os.lstat(self.path)
                    except FileNotFoundError:
                        raise FileExistsError(f"{self.path} was replaced while writing; use -w/--overwrite to overwrite")
                    if (st.st_dev, st.st_ino) != self.created_id:
                        raise FileExistsError(f"{self.path} was replaced while writing; use -w/--overwrite to overwrite")
                self.committed = True
                self._fsync_dir()
            else:
                self.file.close()
        finally:
            if not self.file.closed:
                try:
                    self.file.close()
                except OSError:
                    pass  # never mask the original error
            if not self.committed:
                try:
                    if self.created_id is None:
                        os.unlink(self.created)
                    elif all(self.created_id):
                        st = os.lstat(self.created)
                        if (st.st_dev, st.st_ino) == self.created_id:
                            os.unlink(self.created)
                    # else: identity is unverifiable (st_dev/st_ino == 0 on Windows
                    # FAT/exFAT/WebDAV); refuse rather than unlink a file we can't
                    # prove we own. A failed write leaves a partial file; recovery is -w.
                except OSError:
                    pass  # never mask the original error
        return False

    def _fsync_dir(self):
        if sys.platform == "win32":
            return
        fd = os.open(self.directory, os.O_RDONLY)
        try:
            try:
                os.fsync(fd)
            except OSError as e:
                if e.errno not in _FSYNC_UNSUPPORTED:
                    raise
        finally:
            os.close(fd)
