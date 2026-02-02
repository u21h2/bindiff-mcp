
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
except ImportError as e:
    print(f"Error importing IDALib: {e}", file=sys.stderr)
    sys.exit(1)

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
        
        # 1. Export Function List
        print(f"Exporting functions to {funcs_file}...")
        funcs = {}
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            funcs[ea] = name
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
