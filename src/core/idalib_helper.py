
import sys
import os
import json

# Expected Env Vars: IDADIR, IDALIB_PYTHON
idalib_python = os.environ.get("IDALIB_PYTHON")
if idalib_python and idalib_python not in sys.path:
    sys.path.append(idalib_python)

try:
    import idapro
    import ida_loader
    import idc
    import idautils
    import ida_auto
    import ida_funcs
    import ida_gdl
except ImportError as e:
    print(f"Error importing IDALib: {e}", file=sys.stderr)
    sys.exit(1)

def count_basic_blocks(func):
    """Count the number of basic blocks in a function using its flowchart."""
    try:
        flowchart = ida_gdl.FlowChart(func)
        return sum(1 for _ in flowchart)
    except:
        return 0

def count_instructions(func):
    """Count the number of instructions in a function."""
    try:
        count = 0
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.is_code(idc.get_full_flags(head)):
                count += 1
        return count
    except:
        return 0

def export_binary(binary_path, output_dir):
    print(f"Opening database for {binary_path}...")
    try:
        idapro.open_database(binary_path, True)
    except Exception as e:
        print(f"Failed to open database: {e}", file=sys.stderr)
        sys.exit(1)
    print("Auto-analysis complete.")

    try:
        os.makedirs(output_dir, exist_ok=True)
        filename = os.path.basename(binary_path)
        root, _ = os.path.splitext(filename)
        binexport_file = os.path.join(output_dir, root + ".BinExport")
        funcs_file = os.path.join(output_dir, root + ".functions.json")
        
        # 1. Export Function List with metadata
        print(f"Exporting functions to {funcs_file}...")
        funcs = {}
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if func:
                flags = func.flags
                # Count basic blocks and instructions
                bb_count = count_basic_blocks(func)
                instr_count = count_instructions(func)
                
                funcs[ea] = {
                    "name": idc.get_func_name(ea),
                    "is_lib": bool(flags & ida_funcs.FUNC_LIB),
                    "is_thunk": bool(flags & ida_funcs.FUNC_THUNK),
                    "size": func.end_ea - func.start_ea,
                    "basic_blocks": bb_count,
                    "instructions": instr_count,
                    "flags": flags
                }
            else:
                # Fallback if func object unavailable
                funcs[ea] = {
                    "name": idc.get_func_name(ea),
                    "is_lib": False,
                    "is_thunk": False,
                    "size": 0,
                    "basic_blocks": 0,
                    "instructions": 0,
                    "flags": 0
                }
        with open(funcs_file, "w") as f:
            json.dump(funcs, f, indent=2)

        # 2. BinExport
        print(f"Starting BinExport to {binexport_file}...")

        # Plugin Discovery Logic
        idadir = os.environ.get("IDADIR")
        candidates = []
        
        # Priority 1: Scan IDADIR root and 'plugins' directory for binexport files
        if idadir:
             # Scan directories to find binexport plugin
             scan_dirs = [idadir, os.path.join(idadir, "plugins")]
             for scan_dir in scan_dirs:
                 if os.path.exists(scan_dir):
                     print(f"Scanning for plugins in: {scan_dir}")
                     for f in os.listdir(scan_dir):
                         if "binexport" in f.lower():
                             print(f"Found plugin file: {f}")
                             full_path = os.path.join(scan_dir, f)
                             candidates.append(full_path)            # Absolute path first
                             candidates.append(f)                    # Filename
                             candidates.append(os.path.splitext(f)[0]) # Stem
        
        # Priority 2: Hardcoded Fallbacks (Linux/macOS standard names)
        fallback_names = [
            "binexport12_ida64",       
            "binexport12_ida64.so",
            "binexport12_ida",
            "binexport12_ida.dylib",
            "binexport12", 
            "binexport11", 
            "BinExport"
        ]
        candidates.extend(fallback_names)
        
        # Deduplicate while preserving order
        candidates = list(dict.fromkeys(candidates))
        
        print(f"Plugin load candidates: {candidates}")

        loaded_plugin = None
        for name in candidates:
            try:
                # Skip clearly invalid absolute paths if they don't exist
                if os.path.isabs(name) and not os.path.exists(name):
                    continue
                    
                print(f"Trying load_plugin('{name}')...")
                p = ida_loader.load_plugin(name)
                if p:
                    ida_loader.run_plugin(p, 0)
                    print(f"SUCCESS: Loaded plugin: {name}")
                    loaded_plugin = p
                    break
            except Exception as e:
                # print(f"Error loading {name}: {e}") # Reduce noise
                continue
        
        if not loaded_plugin:
            print("WARNING: Could not explicitly load any BinExport plugin.", file=sys.stderr)

        # IDC Execution
        path_arg = binexport_file.replace("\\", "\\\\")
        idc_cmd = f'BinExportBinary("{path_arg}")'
        print(f"Executing IDC: {idc_cmd}")
        
        try:
            res = idc.eval_idc(idc_cmd)
            print(f"BinExport Result: {res}")
        except Exception as e:
            print(f"IDC execution failed: {e}", file=sys.stderr)

        # Verification
        if os.path.exists(binexport_file):
            print(f"SUCCESS: {binexport_file} created.")
        else:
            print(f"FAILURE: {binexport_file} NOT created.", file=sys.stderr)

    except Exception as e:
        print(f"Export process failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        print("Closing database...")
        idapro.close_database()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)
    export_binary(sys.argv[1], sys.argv[2])
