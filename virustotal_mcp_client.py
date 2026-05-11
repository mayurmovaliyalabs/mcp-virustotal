import argparse
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check_url(url: str, wait_seconds: int) -> None:
    server_path = Path(__file__).with_name("virustotal_mcp_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)],
        env=dict(os.environ),
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "check_url",
                {
                    "url": url,
                    "max_wait_seconds": wait_seconds,
                },
            )

            for item in result.content:
                text = getattr(item, "text", None)
                if text is not None:
                    print(text)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP client for checking a URL with the VirusTotal MCP server."
    )
    parser.add_argument("url", help="URL to check, including http:// or https://")
    parser.add_argument(
        "--wait",
        type=int,
        default=60,
        help="Maximum seconds to wait for VirusTotal analysis to complete.",
    )
    args = parser.parse_args()

    asyncio.run(check_url(args.url, args.wait))


if __name__ == "__main__":
    main()
