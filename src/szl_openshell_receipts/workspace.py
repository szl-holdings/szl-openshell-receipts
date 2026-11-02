"""Rooted POSIX file I/O for the CLI; no symlink-following fallback.

Directory descriptors bind each walk. This is not an OS sandbox: the chosen
workspace and its directories must remain owned by a trusted operator.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import uuid


class Workspace:
    def __init__(self, root):
        if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("secure workspace I/O is unavailable on this platform")
        self.root = Path(root).resolve(strict=True)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        os.close(self.fd)

    def parts(self, value):
        if not isinstance(value, str) or not value or "\\" in value:
            raise ValueError("invalid workspace path")
        if any(ord(char) < 32 for char in value) or ".." in value.split("/"):
            raise ValueError("invalid workspace path")
        path = Path(value)
        if path.is_absolute():
            try:
                path = path.relative_to(self.root)
            except ValueError:
                raise ValueError("path is outside the workspace") from None
        parts = path.parts
        if not parts:
            raise ValueError("file path required")
        return parts

    @contextmanager
    def parent(self, value):
        parts = self.parts(value)
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield fd, parts[-1]
        finally:
            os.close(fd)

    def validate(self, value, *, output=False):
        with self.parent(value) as (fd, name):
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if output:
                    return
                raise
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("regular workspace file required")

    def read_bytes(self, value):
        with self.parent(value) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError("regular workspace file required")
                return source.read()

    def read_text(self, value):
        return self.read_bytes(value).decode("utf-8")

    def write_text(self, value, text):
        with self.parent(value) as (parent, name):
            self.validate(value, output=True)
            temporary = ".szl-receipts-" + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as target:
                    target.write(text)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    # Successful replacement already consumed the temporary name.
                    pass
