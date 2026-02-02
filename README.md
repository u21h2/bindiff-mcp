# BinDiff MCP Tool

A Model Context Protocol (MCP) server that provides binary comparison capabilities using **IDA Pro** and **BinDiff**.

## Features
- **Compare Binaries**: Compare two binary files (e.g., original vs. patched).
- **Function Analysis**: Get a summary of similarity and a list of changed functions.
- **Headless Operation**: Uses IDA Pro in headless mode and IDAPython for automation.


## Installation

### Prerequisites
- **Python 3.10+**
- **IDA Pro** (9.0+ recommended)
- **BinDiff** (installed and capable of running from command line).
- **uv** (recommended for package management).

### Installing BinDiff on Linux (Ubuntu/Debian)
1. Download the latest `.deb` package (e.g., `bindiff_8_amd64.deb`) from the [official releases](https://github.com/google/bindiff/releases).
2. Install using dpkg:
   ```bash
   sudo dpkg -i bindiff_8_amd64.deb
   ```
3. Verify installation:
   ```bash
   which bindiff
   ```

## Platform-Specific Configuration
The tool attempts to auto-detect IDA and BinDiff. You can override these by setting environment variables or editing `src/config.py`.

### macOS
- **IDA Pro**: 9.1 (recommended) or 9.0+.
- **BinDiff**: Installed via installer.
- **Environment**:
  - `IDADIR`: Path to IDA installation (e.g., `/Applications/IDA91/IDA Professional 9.1.app/Contents/MacOS`).
  - `BINDIFF_PATH`: Path to `bindiff` binary (e.g., `/usr/local/bin/bindiff`).

### Linux (Ubuntu etc.)
- **IDA Pro**: 9.0+ installed (e.g., in `/opt/idapro-9.1`).
- **BinDiff**: Installed and accessible.
- **Environment**:
  - `IDADIR`: **Required**. Set to your IDA installation base directory containing `libidalib.so` (e.g., `/opt/idapro-9.1`).
  - `BINDIFF_PATH`: Path to `bindiff` executable (default checks `$PATH`).
  - Ensure `idalib` is present in `$IDADIR/idalib`.

## Configuration
### Environment Variables
- `IDADIR`: Path to the IDA Pro installation directory (containing `idat` and `idalib`).
- `BINDIFF_PATH`: Path to the `bindiff` executable.
- `MCP_TIMEOUT`: Timeout for analysis steps in seconds (default: 3600).

## Installation
1.  Clone this repository.
2.  Install dependencies using `uv`:
    ```bash
    uv sync
    ```

## Usage

### Running Remotely (SSE) - Recommended

Start the server in SSE mode so it can be accessed by remote or local clients via HTTP:

**Linux (Docker/Server)**:
```bash
IDADIR=/app/ida-pro-9.1 BINDIFF_PATH=/usr/bin/bindiff uv run bindiff-mcp --transport sse --host 0.0.0.0 --port 8001
```

**macOS**:
```bash
IDADIR="/Applications/IDA91/IDA Professional 9.1.app/Contents/MacOS" BINDIFF_PATH=/usr/local/bin/bindiff uv run bindiff-mcp --transport sse --host 0.0.0.0 --port 8001
```

### Client Configuration (Antigravity, Claude Desktop, etc.)

Configure your MCP client to connect via the `/sse` endpoint:

```json
{
  "mcpServers": {
    "bindiff-mcp": {
      "type": "remote",
      "url": "http://127.0.0.1:8001/sse"
    }
  }
}
```


## Development
- **Structure**:
    - `src/server.py`: Main MCP server entry point.
    - `src/core/`: Core logic for IDA export, BinDiff execution, and parsing.
    - `src/config.py`: Configuration handling.
