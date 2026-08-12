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
        fd, self.tmp_path = tempfile.mkstemp(prefix=".thrasher-", dir=self.directory)
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
                    os.replace(self.tmp_path, self.path)
                else:
                    os.link(self.tmp_path, self.path)
                    os.unlink(self.tmp_path)
                self._fsync_dir()
            else:
                self.file.close()
        finally:
            if not self.file.closed:
                try:
                    self.file.close()
                except OSError:
                    pass  # never mask the original error
            if os.path.exists(self.tmp_path):
                try:
                    os.unlink(self.tmp_path)
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
