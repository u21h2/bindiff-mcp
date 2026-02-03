import os
import sys
import logging
import asyncio

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
from src.config import config
from src.core.ida_runner import IDARunner
from src.core.bindiff_runner import BinDiffRunner
from src.core.parser import BinDiffParser
from src.utils.temp_manager import temporary_workspace

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bindiff_mcp")

# Initialize FastMCP
mcp = FastMCP("BinDiff Service")

@mcp.tool()
async def bindiff_compare(primary_binary: str, secondary_binary: str, output_results_dir: str = ".") -> str:
    """
    Compares two binary files using IDA Pro and BinDiff.
    Resulting detailed difference lists are saved to the specified directory (default: current directory).
    Generated files:
    1. matched_similar.json (Identical functions)
    2. matched_different.json (Matched but Changed functions)
    3. primary_only.json (Unmatched in Primary)
    4. secondary_only.json (Unmatched in Secondary)
    
    Args:
        primary_binary: Path to the first binary (e.g. original)
        secondary_binary: Path to the second binary (e.g. patched)
        output_results_dir: Directory to save the result files (default: current dir)
    """
    
    # Validate Inputs
    errors = config.validate()
    if errors:
        return f"Configuration Error: {', '.join(errors)}"
        
    if not os.path.exists(primary_binary):
        return f"Error: Primary binary not found at {primary_binary}"
    if not os.path.exists(secondary_binary):
        return f"Error: Secondary binary not found at {secondary_binary}"

    try:
        os.makedirs(output_results_dir, exist_ok=True)
        
        with temporary_workspace() as temp_manager:
            workspace = temp_manager.create_temp_dir()
            logger.info(f"Using workspace: {workspace}")
            
            # 1. & 2. Parallel Export
            ida = IDARunner()
            
            pri_dir = os.path.join(workspace, "primary")
            sec_dir = os.path.join(workspace, "secondary")
            
            print(f"Exporting primary: {primary_binary}")
            print(f"Exporting secondary: {secondary_binary}")
            
            # Run exports in parallel threads (subprocesses block the thread, so this releases the event loop)
            # Use asyncio.to_thread to run the blocking export_binary method in a separate thread
            task_pri = asyncio.to_thread(ida.export_binary, primary_binary, pri_dir)
            task_sec = asyncio.to_thread(ida.export_binary, secondary_binary, sec_dir)
            
            results = await asyncio.gather(task_pri, task_sec)
            primary_export, secondary_export = results

            primary_funcs_json = os.path.splitext(primary_export)[0] + ".functions.json"
            secondary_funcs_json = os.path.splitext(secondary_export)[0] + ".functions.json"
            
            # 3. Run BinDiff
            bindiff = BinDiffRunner()
            print("Running BinDiff...")
            diff_db = await asyncio.to_thread(bindiff.diff_exports, primary_export, secondary_export, workspace)
            
            # 4. Parse Results and Compute Sets
            parser = BinDiffParser(diff_db)
            summary = parser.get_summary()
            
            # Get all matches from DB
            # We need ALL matches to subtract from total functions
            all_matches = parser.get_function_diffs(limit=10000000) # Assuming < 10000k functions
            
            parser.close()
            
            # Read full function lists
            import json
            try:
                with open(primary_funcs_json, 'r') as f:
                    primary_funcs = json.load(f) # {addr: name}
                with open(secondary_funcs_json, 'r') as f:
                    secondary_funcs = json.load(f) # {addr: name}
            except Exception as e:
                return f"Error reading function lists: {e}"

            # Convert keys to int if json load made them strings
            primary_funcs = {int(k): v for k, v in primary_funcs.items()}
            secondary_funcs = {int(k): v for k, v in secondary_funcs.items()}
            
            # Helper function to filter noise (library/thunk functions)
            def get_func_name(func_data):
                """Extract function name from func_data (supports both old and new format)"""
                if isinstance(func_data, str):
                    return func_data
                return func_data.get("name", "")
            
            def should_filter_function(func_data):
                """
                Determine if a function should be filtered out (simulating BinDiff GUI noise reduction).
                Returns True if the function should be excluded from Unmatched results.
                """
                # If we have metadata, use it
                if isinstance(func_data, dict):
                    if func_data.get("is_lib", False):
                        return True
                    if func_data.get("is_thunk", False):
                        return True
                    # Optional: filter very small functions (less than 8 bytes)
                    # if func_data.get("size", 100) < 8:
                    #     return True
                
                # Heuristic filtering based on naming conventions
                name = get_func_name(func_data)
                
                # Thunk functions (IDA typically names them with j_ prefix)
                if name.startswith("j_") or name.startswith("."):
                    return True
                # PLT functions
                if ".plt" in name or "@plt" in name:
                    return True
                # Common library function prefixes (auto-labeled by IDA)
                # Exclude C++ mangled names (__Z...)
                if name.startswith("__") and not name.startswith("__Z"):
                    return True
                # Null/stub functions
                if name.startswith("nullsub_") or name.startswith("_nullsub_"):
                    return True
                # Import stubs
                if name.startswith("_") and name[1:2].isupper():
                    # Pattern like _Printf, _Malloc - often import stubs
                    pass  # Don't filter these aggressively
                    
                return False
            
            # Organize Data
            identical = []
            changed = []
            matched_pri_addrs = set()
            matched_sec_addrs = set()
            
            for m in all_matches:
                addr1 = m['address1']
                addr2 = m['address2']
                similarity = m['similarity']
                
                matched_pri_addrs.add(addr1)
                matched_sec_addrs.add(addr2)
                
                # Get names from our exported data (supports both old and new format)
                pri_data = primary_funcs.get(addr1)
                sec_data = secondary_funcs.get(addr2)
                name1 = get_func_name(pri_data) if pri_data else f"sub_{addr1:x}"
                name2 = get_func_name(sec_data) if sec_data else f"sub_{addr2:x}"
                
                item = {
                    "address1": addr1,
                    "name1": name1,
                    "address2": addr2,
                    "name2": name2,
                    "similarity": similarity,
                    "confidence": m.get('confidence', 0.0),
                    "algorithm": m.get('algorithm', 'unknown'),
                    "basicblocks": m.get('basicblocks', 0),
                    "edges": m.get('edges', 0),
                    "instructions": m.get('instructions', 0)
                }
                
                if similarity >= 0.999: # Treat 1.0ish as identical
                    identical.append(item)
                else:
                    changed.append(item)
            
            # Sort changed by similarity descending (High -> Low)
            changed.sort(key=lambda x: x['similarity'], reverse=True)
                    
            # Compute Unmatched (with noise filtering)
            def get_func_metadata(func_data):
                """Extract extended metadata from func_data for unmatched functions."""
                if isinstance(func_data, dict):
                    return {
                        "basic_blocks": func_data.get("basic_blocks", 0),
                        "instructions": func_data.get("instructions", 0),
                        "size": func_data.get("size", 0)
                    }
                return {"basic_blocks": 0, "instructions": 0, "size": 0}
            
            primary_only = []
            filtered_primary_count = 0
            for addr, func_data in primary_funcs.items():
                if addr in matched_pri_addrs:
                    continue
                if should_filter_function(func_data):
                    filtered_primary_count += 1
                    continue
                meta = get_func_metadata(func_data)
                primary_only.append({
                    "address": addr, 
                    "name": get_func_name(func_data),
                    "basic_blocks": meta["basic_blocks"],
                    "instructions": meta["instructions"],
                    "size": meta["size"]
                })
                    
            secondary_only = []
            filtered_secondary_count = 0
            for addr, func_data in secondary_funcs.items():
                if addr in matched_sec_addrs:
                    continue
                if should_filter_function(func_data):
                    filtered_secondary_count += 1
                    continue
                meta = get_func_metadata(func_data)
                secondary_only.append({
                    "address": addr, 
                    "name": get_func_name(func_data),
                    "basic_blocks": meta["basic_blocks"],
                    "instructions": meta["instructions"],
                    "size": meta["size"]
                })
            
            logger.info(f"Filtered {filtered_primary_count} noise functions from primary")
            logger.info(f"Filtered {filtered_secondary_count} noise functions from secondary")
            
            # Write Files
            import json
            
            def save_json(name, data):
                path = os.path.join(output_results_dir, name)
                with open(path, 'w') as f:
                    json.dump(data, f, indent=2)
                return path

            f1 = save_json("matched_similar.json", identical)
            f2 = save_json("matched_different.json", changed)
            f3 = save_json("primary_only.json", primary_only)
            f4 = save_json("secondary_only.json", secondary_only)
            
            # Format Output Summary
            result = [
                "# BinDiff Analysis Completed",
                f"**Output Directory**: `{os.path.abspath(output_results_dir)}`",
                "",
                "## Summary Statistics",
                f"- **Overall Similarity**: {summary['overall_similarity']:.2f}",
                f"- **Identical Functions**: {len(identical)}",
                f"- **Changed Functions**: {len(changed)}",
                f"- **Primary Only**: {len(primary_only)}",
                f"- **Secondary Only**: {len(secondary_only)}",
                "",
                "## Generated Files",
                f"1. [matched_similar.json](file://{f1})",
                f"2. [matched_different.json](file://{f2})",
                f"3. [primary_only.json](file://{f3})",
                f"4. [secondary_only.json](file://{f4})"
            ]
                 
            return "\n".join(result)

    except Exception as e:
        logger.exception("Comparison failed")
        return f"Error during comparison: {str(e)}"

def main():
    """Entry point for the bindiff-mcp CLI."""
    import argparse
    parser = argparse.ArgumentParser(description="BinDiff MCP Server")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"], help="Transport mode")
    parser.add_argument("--host", default="0.0.0.0", help="Host for SSE server")
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE server")
    
    args = parser.parse_args()
    
    if args.transport == "sse":
        print(f"Starting SSE server 2on {args.host}:{args.port}")
        # FastMCP.run() doesn't accept host/port, they are in settings
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
