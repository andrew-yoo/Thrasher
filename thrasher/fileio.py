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
        self.path = path
        self.overwrite = overwrite
        self.directory = os.path.dirname(os.path.abspath(path))
        self.created = None
        self.created_id = None
        self.committed = False
        if overwrite:
            fd, self.created = tempfile.mkstemp(prefix=".thrasher-", dir=self.directory)
        else:
            # File is written in place, and non-atomic, but never destroys pre-existing data.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.created = path
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
                    elif (os.lstat(self.created).st_dev, os.lstat(self.created).st_ino) == self.created_id:
                        os.unlink(self.created)
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
