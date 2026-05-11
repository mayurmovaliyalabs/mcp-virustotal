import asyncio
import json
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


VT_API_URL = "https://www.virustotal.com/api/v3"

mcp = FastMCP("virustotal-url-checker")


class VirusTotalError(Exception):
    """Raised when VirusTotal returns an error response."""


def _verdict_from_stats(stats: dict[str, int]) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    if harmless > 0 and malicious == 0 and suspicious == 0:
        return "benign"
    if undetected > 0:
        return "unknown"
    return "unknown"


def _compact_result(url: str, analysis: dict[str, Any]) -> dict[str, Any]:
    attributes = analysis.get("data", {}).get("attributes", {})
    stats = attributes.get("stats", {})
    results = attributes.get("results", {})

    flagged_engines = [
        {
            "engine": engine,
            "category": details.get("category"),
            "result": details.get("result"),
        }
        for engine, details in results.items()
        if details.get("category") in {"malicious", "suspicious"}
    ]

    return {
        "url": url,
        "verdict": _verdict_from_stats(stats),
        "stats": stats,
        "analysis_id": analysis.get("data", {}).get("id"),
        "status": attributes.get("status"),
        "flagged_engines": flagged_engines[:20],
    }


async def _vt_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    api_key: str,
    **kwargs: Any,
) -> dict[str, Any]:
    response = await client.request(
        method,
        f"{VT_API_URL}{path}",
        headers={"x-apikey": api_key},
        **kwargs,
    )

    if response.status_code >= 400:
        try:
            details = response.json()
        except ValueError:
            details = response.text
        raise VirusTotalError(f"VirusTotal API error {response.status_code}: {details}")

    return response.json()


async def _submit_url(client: httpx.AsyncClient, api_key: str, url: str) -> str:
    payload = await _vt_request(
        client,
        "POST",
        "/urls",
        api_key,
        data={"url": url},
    )
    analysis_id = payload.get("data", {}).get("id")
    if not analysis_id:
        raise VirusTotalError(f"VirusTotal did not return an analysis id: {payload}")
    return analysis_id


async def _wait_for_analysis(
    client: httpx.AsyncClient,
    api_key: str,
    analysis_id: str,
    max_wait_seconds: int,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + max_wait_seconds
    last_analysis: dict[str, Any] | None = None

    while True:
        analysis = await _vt_request(client, "GET", f"/analyses/{analysis_id}", api_key)
        last_analysis = analysis
        status = analysis.get("data", {}).get("attributes", {}).get("status")

        if status == "completed":
            return analysis

        if asyncio.get_running_loop().time() >= deadline:
            return last_analysis

        await asyncio.sleep(3)


@mcp.tool()
async def check_url(url: str, max_wait_seconds: int = 60) -> str:
    """Submit a URL to VirusTotal and return whether it appears benign or malicious."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return json.dumps(
            {
                "error": "Missing VT_API_KEY environment variable.",
                "hint": "Set VT_API_KEY to your VirusTotal API key before running the MCP server.",
            },
            indent=2,
        )

    if not url.startswith(("http://", "https://")):
        return json.dumps(
            {
                "error": "URL must start with http:// or https://",
                "url": url,
            },
            indent=2,
        )

    max_wait_seconds = max(0, min(max_wait_seconds, 300))

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            analysis_id = await _submit_url(client, api_key, url)
            analysis = await _wait_for_analysis(
                client,
                api_key,
                analysis_id,
                max_wait_seconds,
            )
            return json.dumps(_compact_result(url, analysis), indent=2)
    except VirusTotalError as exc:
        return json.dumps({"error": str(exc)}, indent=2)
    except httpx.HTTPError as exc:
        return json.dumps({"error": f"Network error calling VirusTotal: {exc}"}, indent=2)


if __name__ == "__main__":
    mcp.run()
