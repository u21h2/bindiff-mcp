
import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client

async def run():
    # Configuration
    # Make sure these paths are absolute
    base_dir = os.path.dirname(os.path.abspath(__file__))
    primary = os.path.join(base_dir, "test_examples", "samld-748")
    secondary = os.path.join(base_dir, "test_examples", "samld-749")
    output_dir = os.path.join(base_dir, "test_examples", "results")
    
    server_url = "http://127.0.0.1:8001/sse"

    print(f"Connecting to {server_url}...")
    print(f"Primary: {primary}")
    print(f"Secondary: {secondary}")
    
    try:
        async with sse_client(server_url) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                print("Connected! Listing tools...")
                tools = await session.list_tools()
                for t in tools.tools:
                    print(f"- {t.name}: {t.description}")
                
                print("\nCalling bindiff_compare...")
                # Note: The server might take a while, so ensure the client doesn't timeout if it has one.
                # The MCP python client usually doesn't have a short default timeout for calls.
                
                result = await session.call_tool(
                    "bindiff_compare",
                    arguments={
                        "primary_binary": primary,
                        "secondary_binary": secondary,
                        "output_results_dir": output_dir
                    }
                )
                
                print("\n=== Result ===")
                for content in result.content:
                    if content.type == "text":
                        print(content.text)
                    else:
                        print(f"[{content.type}] {content}")
                        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if not os.path.exists("test_examples/samld-748") or not os.path.exists("test_examples/samld-749"):
        print("Error: Test binaries not found in test_examples/")
        sys.exit(1)
        
    asyncio.run(run())
