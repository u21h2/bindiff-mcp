import tempfile
import shutil
import os
from contextlib import contextmanager

class TempManager:
    def __init__(self):
        self.temp_dirs = []

    def create_temp_dir(self):
        """Creates a temporary directory and tracks it for cleanup."""
        temp_dir = tempfile.mkdtemp(prefix="bindiff_mcp_")
        self.temp_dirs.append(temp_dir)
        return temp_dir

    def cleanup(self):
        """Removes all tracked temporary directories."""
        for path in self.temp_dirs:
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
        self.temp_dirs = []

@contextmanager
def temporary_workspace():
    manager = TempManager()
    try:
        yield manager
    finally:
        manager.cleanup()
