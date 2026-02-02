import os
import sys
import platform
import shutil
from pathlib import Path

class Config:
    def __init__(self):
        self.system = platform.system()
        self.ida_dir = self._find_ida_dir()
        self.idalib_python = self._find_idalib_python()
        self.bindiff_path = self._find_bindiff()
        self.timeout = int(os.environ.get("MCP_TIMEOUT", 36000))
        
    def _find_ida_dir(self):
        """Finds the IDA installation directory for idalib."""
        ida_dir_env = os.environ.get("IDADIR")
        if ida_dir_env and os.path.exists(ida_dir_env):
            return ida_dir_env

        # Default for IDA 9.1 on macOS
        if self.system == "Darwin":
            default_path = "/Applications/IDA91/IDA Professional 9.1.app/Contents/MacOS"
            if os.path.exists(default_path):
                return default_path
                
        # TODO: Add Windows/Linux defaults if needed, user focused on macOS IDA 9.1
        return None

    def _find_idalib_python(self):
        """Finds the idalib python directory."""
        if self.ida_dir:
            path = os.path.join(self.ida_dir, "idalib", "python")
            if os.path.exists(path):
                return path
        return None

    def _find_bindiff(self):
        """Finds the BinDiff executable."""
        bindiff_env = os.environ.get("BINDIFF_PATH")
        if bindiff_env and os.path.exists(bindiff_env):
            return bindiff_env
            
        if self.system == "Darwin":
            return "/usr/local/bin/bindiff"
        
        return shutil.which("bindiff")

    def validate(self):
        errors = []
        if not self.ida_dir:
            errors.append("IDA Pro directory not found. Set IDADIR environment variable.")
        if not self.idalib_python:
            errors.append("IDALib Python directory not found inside IDA installation.")
        if not self.bindiff_path:
            errors.append("BinDiff executable not found. Set BINDIFF_PATH environment variable.")
        return errors
        
    def setup_idalib(self):
        """Sets up the environment for idalib."""
        if self.ida_dir and self.idalib_python:
            os.environ["IDADIR"] = self.ida_dir
            if self.idalib_python not in sys.path:
                sys.path.append(self.idalib_python)


config = Config()
