# VirusTotal MCP URL Checker

This project contains a Python MCP server and MCP client that check whether a URL appears benign, suspicious, malicious, or unknown using VirusTotal.

## Files

- `virustotal_mcp_server.py` exposes an MCP tool named `check_url`.
- `virustotal_mcp_client.py` starts the server over stdio and calls that tool.
- `requirements.txt` lists the Python dependencies.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export VT_API_KEY="your_virustotal_api_key_here"
```

## Run

```bash
python virustotal_mcp_client.py "https://example.com"
```

You can change how long the client waits for VirusTotal to finish the scan:

```bash
python virustotal_mcp_client.py "https://example.com" --wait 120
```

## Example Output

```json
{
  "url": "https://example.com",
  "verdict": "benign",
  "stats": {
    "malicious": 0,
    "suspicious": 0,
    "undetected": 30,
    "harmless": 65,
    "timeout": 0
  },
  "analysis_id": "example-analysis-id",
  "status": "completed",
  "flagged_engines": []
}
```

## Verdict Logic

- `malicious`: one or more engines flagged the URL as malicious.
- `suspicious`: no malicious flags, but one or more suspicious flags.
- `benign`: at least one harmless result and no malicious or suspicious flags.
- `unknown`: no clear harmless, suspicious, or malicious signal.

VirusTotal results are reputation signals from third-party engines, not a guarantee. Treat the verdict as one input in a larger security decision.
