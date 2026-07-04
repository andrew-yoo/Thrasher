def write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
