import os
import sys
import subprocess
import logging
import time
from src.config import config

logger = logging.getLogger("bindiff_mcp.ida_runner")

# IDAPython script to run inside IDA for export
# This script loads the BinExport plugin and exports the database.
EXPORT_SCRIPT_CONTENT = """
import ida_auto
import ida_pro
import ida_loader
import os

def main():
    ida_auto.auto_wait()
    
    # Ensure correct plugin loading
    # Note: Plugin name might vary slightly depending on version/installation
    # "binexport12" or similar. Usually loading via idc is reliable if installed.
    
    # Try to load BinExport plugin
    # Depending on IDA version, we might need to load it explicitly or it might be auto-loaded.
    # We will try to invoke the export action.
    
    input_file = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    root, _ = os.path.splitext(input_file)
    binexport_file = root + ".BinExport"
    
    print(f"Attempting to export to: {binexport_file}")
    
    # This is the standard way to trigger BinExport in recent versions
    # 0x0 arg means "export to file" (implied default behavior?)
    # Actually, BinExport is often an IDAPython plugin or C++ plugin.
    # Checking for the plugin:
    
    from ida_idp import IDP_interface
    
    # Trigger BinExport. 
    # NOTE: Command args are specific to the plugin version. 
    # Often simply loading the plugin with right arguments works.
    
    # Alternative: use idc.load_and_run_plugin
    # Reference: https://github.com/google/bindiff/tree/main/ida
    
    # A generic approach for newer BinExport:
    import idc
    
    # This invokes the plugin. 'BinExportBinary' is often the edit var name or command.
    # The headless export usually requires passing arguments specific to the plugin.
    # For BinExport 12+:
    
    ret = idc.load_and_run_plugin("binexport12", 0) # Try 12
    if ret == 0:
         ret = idc.load_and_run_plugin("binexport11", 0) # Try 11
    if ret == 0:
         ret = idc.load_and_run_plugin("zynamics_binexport_9", 0) # Try older
         
    # However, newer BinExport might just need to be called.
    # Let's try the modern standard:
    # It auto-exports if configured, but we want to force it.
    
    try:
        import binexport
        binexport.export_file(binexport_file)
        print("Export successful via python module.")
    except ImportError:
        print("BinExport python module not found. Trying plugin call...")
        # Fallback to IDC
        # This is tricky without specific version. 
        # But we will assume the environment has it set up to auto-run or we use a standard call.
        pass

    # Wait for analysis to finish (auto_wait above) and then exit
    ida_pro.qexit(0)

if __name__ == "__main__":
    main()
"""

from ..config import config

logger = logging.getLogger(__name__)

class IDARunner:
    def __init__(self):
        # We don't need ida_path anymore, we use idalib
        # Env setup is handled by config or before running subprocess
        pass

    def export_binary(self, binary_path, output_dir):
        """
        Runs idalib via a helper script to generate a .BinExport file.
        Returns the path to the generated .BinExport file.
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
            
        os.makedirs(output_dir, exist_ok=True)
        
        # Helper script path
        # Assume it's in the same directory as this file
        helper_script = os.path.join(os.path.dirname(__file__), "idalib_helper.py")
        
        # Prepare Environment
        env = os.environ.copy()
        if config.ida_dir:
            env["IDADIR"] = config.ida_dir
        if config.idalib_python:
            env["IDALIB_PYTHON"] = config.idalib_python
            
        cmd = [
            sys.executable,
            helper_script,
            binary_path,
            output_dir
        ]
        
        logger.info(f"Running IDALib Helper: {' '.join(cmd)}")
        
        try:
            print("timeout", config.timeout)
            start_time = time.time()
            print("current_time", start_time)
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=config.timeout) # Use configured timeout
            end_time = time.time()
            print("end_time", end_time)
            print("time_consumed", (end_time - start_time) / 60, "minutes")   
            logger.debug("IDALib Output: " + result.stdout)
            if result.returncode != 0:
                print(f"IDALib Return Code: {result.returncode}")
                logger.error(f"IDALib failed with return code {result.returncode}")
                logger.error("IDALib Error: " + result.stderr)
                print("IDALib Error: " + result.stderr)
                print("IDALib Output: " + result.stdout)
                raise RuntimeError(f"IDALib failed (code {result.returncode}): {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error("IDALib execution timed out")
            raise

        # Check for result
        # BinExport typically adds .BinExport to the database name or binary name
        target_bin_path = os.path.join(output_dir, os.path.basename(binary_path))
        
        possible_names = [
            target_bin_path + ".BinExport",
            os.path.splitext(target_bin_path)[0] + ".BinExport"
        ]
        
        for p in possible_names:
            if os.path.exists(p):
                return p
                
        raise RuntimeError("BinExport file was not generated. Check IDA logs.")
