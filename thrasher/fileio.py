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
        directory = os.path.dirname(os.path.abspath(path))
        fd, self.tmp_path = tempfile.mkstemp(prefix=".thrasher-", dir=directory)
        self.file = os.fdopen(fd, "wb")

    def __enter__(self):
        return self.file

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.file.flush()
            os.fsync(self.file.fileno())
            self.file.close()
            os.replace(self.tmp_path, self.path)
        else:
            self.file.close()
            os.unlink(self.tmp_path)
        return False
