# mcp-server-sentry: A Sentry MCP server

## Overview

A Model Context Protocol server for retrieving and analyzing issues from Sentry.io. This server provides tools to inspect error reports, stacktraces, and other debugging information from your Sentry account.

### Tools

1. `get_sentry_issue`
   - Retrieve and analyze a Sentry issue by ID or URL
   - Input:
     - `issue_id_or_url` (string): Sentry issue ID or URL to analyze
   - Returns: Issue details including:
     - Title
     - Issue ID
     - Status
     - Level
     - First seen timestamp
     - Last seen timestamp
     - Event count
     - Full stacktrace

2. `query_sentry_issues`
   - Search for Sentry issues with filters
   - Input:
     - `query` (string, optional): Search query to find specific issues
     - `status` (string, optional): Filter by status (unresolved, resolved, ignored)
     - `level` (string, optional): Filter by error level (error, warning, info)
     - `project` (string, optional): Filter by project identifier
     - `limit` (integer, optional): Maximum number of issues to return (default: 10)
   - Returns: List of issues matching the criteria, including:
     - Title
     - Issue ID
     - Project name
     - Status
     - Level
     - Event count
     - First/last seen timestamps
     - Issue URL

3. `list_latest_sentry_issues`
   - List the most recent Sentry issues
   - Input:
     - `limit` (integer, optional): Maximum number of issues to return (default: 10)
   - Returns: List of the most recent issues with the same fields as above

### Prompts

1. `sentry-issue`
   - Retrieve issue details from Sentry
   - Input:
     - `issue_id_or_url` (string): Sentry issue ID or URL
   - Returns: Formatted issue details as conversation context

## Installation

### Using uv (recommended)

When using [`uv`](https://docs.astral.sh/uv/) no specific installation is needed. We will
use [`uvx`](https://docs.astral.sh/uv/guides/tools/) to directly run *mcp-server-sentry*.

### Using PIP

Alternatively you can install `mcp-server-sentry` via pip:

```
pip install mcp-server-sentry
```

After installation, you can run it as a script using:

```
python -m mcp_server_sentry
```

## Configuration

### Usage with Claude Desktop

Add this to your `claude_desktop_config.json`:

<details>
<summary>Using uvx</summary>

```json
"mcpServers": {
  "sentry": {
    "command": "uvx",
    "args": ["mcp-server-sentry", "--auth-token", "YOUR_SENTRY_TOKEN"]
  }
}
```
</details>

<details>

<details>
<summary>Using docker</summary>

```json
"mcpServers": {
  "sentry": {
    "command": "docker",
    "args": ["run", "-i", "--rm", "mcp/sentry", "--auth-token", "YOUR_SENTRY_TOKEN"]
  }
}
```
</details>

<details>

<summary>Using pip installation</summary>

```json
"mcpServers": {
  "sentry": {
    "command": "python",
    "args": ["-m", "mcp_server_sentry", "--auth-token", "YOUR_SENTRY_TOKEN"]
  }
}
```
</details>

### Usage with [Zed](https://github.com/zed-industries/zed)

Add to your Zed settings.json:

<details>
<summary>Using uvx</summary>

```json
"context_servers": [
  "mcp-server-sentry": {
    "command": {
      "path": "uvx",
      "args": ["mcp-server-sentry", "--auth-token", "YOUR_SENTRY_TOKEN"]
    }
  }
],
```
</details>

<details>
<summary>Using pip installation</summary>

```json
"context_servers": {
  "mcp-server-sentry": {
    "command": "python",
    "args": ["-m", "mcp_server_sentry", "--auth-token", "YOUR_SENTRY_TOKEN"]
  }
},
```
</details>

## Examples

### Retrieving a specific issue

```
Use the get_sentry_issue tool to examine the details of issue 1234567890
```

### Querying issues with filters

```
Use the query_sentry_issues tool to find all unresolved error-level issues containing the text "database connection"
```

### Listing the most recent issues

```
Use the list_latest_sentry_issues tool to show me the 5 most recent Sentry issues
```

## Debugging

You can use the MCP inspector to debug the server. For uvx installations:

```
npx @modelcontextprotocol/inspector uvx mcp-server-sentry --auth-token YOUR_SENTRY_TOKEN
```

Or if you've installed the package in a specific directory or are developing on it:

```
cd path/to/servers/src/sentry
npx @modelcontextprotocol/inspector uv run mcp-server-sentry --auth-token YOUR_SENTRY_TOKEN
```

## License

This MCP server is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.
