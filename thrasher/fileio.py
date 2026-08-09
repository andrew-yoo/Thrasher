import os
import tempfile


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
    def __init__(self, path: str) -> None:
        self.path = path
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
                os.replace(self.tmp_path, self.path)
                self._fsync_dir()
            else:
                self.file.close()
        finally:
            if os.path.exists(self.tmp_path):
                try:
                    os.unlink(self.tmp_path)
                except OSError:
                    pass  # never mask the original error
        return False

    def _fsync_dir(self):
        try:
            fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass  # dir fsync unsupported on some platforms
