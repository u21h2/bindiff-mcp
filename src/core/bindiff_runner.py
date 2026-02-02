import os
import subprocess
import logging
from src.config import config

logger = logging.getLogger("bindiff_mcp.bindiff_runner")

class BinDiffRunner:
    def __init__(self):
        self.bindiff_path = config.bindiff_path
        if not self.bindiff_path:
            raise RuntimeError("BinDiff Path not configured")

    def diff_exports(self, primary_export, secondary_export, output_dir):
        """
        Runs BinDiff to compare two .BinExport files.
        Returns the path to the generated .BinDiff SQLite database.
        """
        if not os.path.exists(primary_export):
            raise FileNotFoundError(f"Primary export not found: {primary_export}")
        if not os.path.exists(secondary_export):
            raise FileNotFoundError(f"Secondary export not found: {secondary_export}")
            
        # BinDiff usage: bindiff --primary=<path> --secondary=<path> --output_dir=<path>
        # Note: Valid flags depend on BinDiff version.
        
        cmd = [
            self.bindiff_path,
            f"--primary={primary_export}",
            f"--secondary={secondary_export}",
            f"--output_dir={output_dir}"
        ]
        
        logger.info(f"Running BinDiff: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            logger.debug("BinDiff Output: " + result.stdout)
            if result.returncode != 0:
                 # Check if it's just a warning or real error? 
                 # BinDiff returns 0 on success.
                 logger.error("BinDiff Error: " + result.stderr)
        except subprocess.TimeoutExpired:
            logger.error("BinDiff execution timed out")
            raise
            
        # Identifying the output file
        # Usually named: <primary_name>_vs_<secondary_name>.BinDiff
        # We search the output dir for the newest .BinDiff file
        
        candidates = [f for f in os.listdir(output_dir) if f.endswith(".BinDiff")]
        if not candidates:
             raise RuntimeError("BinDiff output file not found.")
             
        # If there are multiple, get the one matching our inputs ideally, or just the one we just made.
        # Since we use a temp dir for output, it should be the only one.
        
        return os.path.join(output_dir, candidates[0])
