import asyncio
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, urlencode

import click
import httpx
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.shared.exceptions import McpError
import mcp.server.stdio

SENTRY_API_BASE = "https://sentry.io/api/0/"
MISSING_AUTH_TOKEN_MESSAGE = (
    """Sentry authentication token not found. Please specify your Sentry auth token."""
)


@dataclass
class SentryIssueData:
    title: str
    issue_id: str
    status: str
    level: str
    first_seen: str
    last_seen: str
    count: int
    stacktrace: str

    def to_text(self) -> str:
        return f"""
Sentry Issue: {self.title}
Issue ID: {self.issue_id}
Status: {self.status}
Level: {self.level}
First Seen: {self.first_seen}
Last Seen: {self.last_seen}
Event Count: {self.count}

{self.stacktrace}
        """

    def to_prompt_result(self) -> types.GetPromptResult:
        return types.GetPromptResult(
            description=f"Sentry Issue: {self.title}",
            messages=[
                types.PromptMessage(
                    role="user", content=types.TextContent(type="text", text=self.to_text())
                )
            ],
        )

    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


@dataclass
class SentryIssueListItem:
    title: str
    issue_id: str
    status: str
    level: str
    first_seen: str
    last_seen: str
    count: int
    permalink: str
    project: str

    @classmethod
    def from_api_response(cls, issue: dict) -> "SentryIssueListItem":
        return cls(
            title=issue.get("title", "Unknown Title"),
            issue_id=str(issue.get("id", "Unknown")),
            status=issue.get("status", "Unknown"),
            level=issue.get("level", "Unknown"),
            first_seen=issue.get("firstSeen", "Unknown"),
            last_seen=issue.get("lastSeen", "Unknown"),
            count=issue.get("count", 0),
            permalink=issue.get("permalink", ""),
            project=issue.get("project", {}).get("slug", "Unknown Project")
        )


@dataclass
class SentryIssuesList:
    issues: List[SentryIssueListItem]
    total_count: int
    query_filters: Optional[dict] = None

    def to_text(self) -> str:
        if not self.issues:
            return "No issues found matching your criteria."
        
        filter_text = ""
        if self.query_filters:
            filter_text = "Filters applied: "
            filter_parts = []
            for key, value in self.query_filters.items():
                if value:
                    filter_parts.append(f"{key}={value}")
            filter_text += ", ".join(filter_parts)
            filter_text += "\n\n"
        
        header = f"Found {self.total_count} Sentry issues. Showing {len(self.issues)} results.\n{filter_text}"
        
        issue_texts = []
        for idx, issue in enumerate(self.issues, 1):
            issue_text = (
                f"{idx}. Issue: {issue.title}\n"
                f"   ID: {issue.issue_id}\n"
                f"   Project: {issue.project}\n"
                f"   Status: {issue.status} | Level: {issue.level}\n"
                f"   Events: {issue.count} | First seen: {issue.first_seen} | Last seen: {issue.last_seen}\n"
                f"   URL: {issue.permalink}\n"
            )
            issue_texts.append(issue_text)
        
        return header + "\n" + "\n".join(issue_texts)

    def to_tool_result(self) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return [types.TextContent(type="text", text=self.to_text())]


class SentryError(Exception):
    pass


def extract_issue_id(issue_id_or_url: str) -> str:
    """
    Extracts the Sentry issue ID from either a full URL or a standalone ID.

    This function validates the input and returns the numeric issue ID.
    It raises SentryError for invalid inputs, including empty strings,
    non-Sentry URLs, malformed paths, and non-numeric IDs.
    """
    if not issue_id_or_url:
        raise SentryError("Missing issue_id_or_url argument")

    if issue_id_or_url.startswith(("http://", "https://")):
        parsed_url = urlparse(issue_id_or_url)
        if not parsed_url.hostname or not parsed_url.hostname.endswith(".sentry.io"):
            raise SentryError("Invalid Sentry URL. Must be a URL ending with .sentry.io")

        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 2 or path_parts[0] != "issues":
            raise SentryError(
                "Invalid Sentry issue URL. Path must contain '/issues/{issue_id}'"
            )

        issue_id = path_parts[-1]
    else:
        issue_id = issue_id_or_url

    if not issue_id.isdigit():
        raise SentryError("Invalid Sentry issue ID. Must be a numeric value.")

    return issue_id


def create_stacktrace(latest_event: dict) -> str:
    """
    Creates a formatted stacktrace string from the latest Sentry event.

    This function extracts exception information and stacktrace details from the
    provided event dictionary, formatting them into a human-readable string.
    It handles multiple exceptions and includes file, line number, and function
    information for each frame in the stacktrace.

    Args:
        latest_event (dict): A dictionary containing the latest Sentry event data.

    Returns:
        str: A formatted string containing the stacktrace information,
             or "No stacktrace found" if no relevant data is present.
    """
    stacktraces = []
    for entry in latest_event.get("entries", []):
        if entry["type"] != "exception":
            continue

        exception_data = entry["data"]["values"]
        for exception in exception_data:
            exception_type = exception.get("type", "Unknown")
            exception_value = exception.get("value", "")
            stacktrace = exception.get("stacktrace")

            stacktrace_text = f"Exception: {exception_type}: {exception_value}\n\n"
            if stacktrace:
                stacktrace_text += "Stacktrace:\n"
                for frame in stacktrace.get("frames", []):
                    filename = frame.get("filename", "Unknown")
                    lineno = frame.get("lineNo", "?")
                    function = frame.get("function", "Unknown")

                    stacktrace_text += f"{filename}:{lineno} in {function}\n"

                    if "context" in frame:
                        context = frame["context"]
                        for ctx_line in context:
                            stacktrace_text += f"    {ctx_line[1]}\n"

                    stacktrace_text += "\n"

            stacktraces.append(stacktrace_text)

    return "\n".join(stacktraces) if stacktraces else "No stacktrace found"


async def handle_sentry_issue(
    http_client: httpx.AsyncClient, auth_token: str, issue_id_or_url: str
) -> SentryIssueData:
    try:
        issue_id = extract_issue_id(issue_id_or_url)

        response = await http_client.get(
            f"issues/{issue_id}/", headers={"Authorization": f"Bearer {auth_token}"}
        )
        if response.status_code == 401:
            raise McpError(
                "Error: Unauthorized. Please check your MCP_SENTRY_AUTH_TOKEN token."
            )
        response.raise_for_status()
        issue_data = response.json()

        # Get issue hashes
        hashes_response = await http_client.get(
            f"issues/{issue_id}/hashes/",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        hashes_response.raise_for_status()
        hashes = hashes_response.json()

        if not hashes:
            raise McpError("No Sentry events found for this issue")

        latest_event = hashes[0]["latestEvent"]
        stacktrace = create_stacktrace(latest_event)

        return SentryIssueData(
            title=issue_data["title"],
            issue_id=issue_id,
            status=issue_data["status"],
            level=issue_data["level"],
            first_seen=issue_data["firstSeen"],
            last_seen=issue_data["lastSeen"],
            count=issue_data["count"],
            stacktrace=stacktrace
        )

    except SentryError as e:
        raise McpError(str(e))
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error fetching Sentry issue: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def query_sentry_issues(
    http_client: httpx.AsyncClient, 
    auth_token: str, 
    query: Optional[str] = None, 
    status: Optional[str] = None,
    level: Optional[str] = None,
    project: Optional[str] = None,
    limit: int = 10
) -> SentryIssuesList:
    """
    Query Sentry issues based on various filters.
    
    Args:
        http_client: HTTPX client with base URL set
        auth_token: Sentry auth token
        query: Optional search query
        status: Optional status filter (unresolved, resolved, ignored)
        level: Optional error level filter (error, warning, info)
        project: Optional project identifier
        limit: Maximum number of issues to return (default 10)
        
    Returns:
        SentryIssuesList: A list of issues matching the query
    """
    try:
        # Build query parameters
        params = {}
        if query:
            params["query"] = query
        if status:
            params["status"] = status
        if level:
            params["level"] = level
        if project:
            params["project"] = project
        
        # Set pagination
        params["limit"] = limit
        
        # Build URL with query parameters
        url = f"projects/issues/?{urlencode(params)}"
        
        # Make API request
        response = await http_client.get(
            url, headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your Sentry authentication token.")
        
        response.raise_for_status()
        issues_data = response.json()
        
        # Parse response
        issues = []
        for issue in issues_data:
            issues.append(SentryIssueListItem.from_api_response(issue))
        
        return SentryIssuesList(
            issues=issues,
            total_count=len(issues),  # In real implementation, this would come from pagination info
            query_filters={
                "query": query,
                "status": status,
                "level": level,
                "project": project
            }
        )
        
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error querying Sentry issues: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def list_latest_sentry_issues(
    http_client: httpx.AsyncClient,
    auth_token: str,
    limit: int = 10
) -> SentryIssuesList:
    """
    List the most recent Sentry issues.
    
    Args:
        http_client: HTTPX client with base URL set
        auth_token: Sentry auth token
        limit: Maximum number of issues to return (default 10)
        
    Returns:
        SentryIssuesList: A list of the most recent issues
    """
    try:
        # Build URL with query parameters to sort by most recent
        params = {
            "limit": limit,
            "sort": "date",  # Sort by date - most recent first
            "statsPeriod": "14d"  # Get issues from the last 14 days
        }
        
        url = f"issues/?{urlencode(params)}"
        
        # Make API request
        response = await http_client.get(
            url, headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 401:
            raise McpError("Error: Unauthorized. Please check your Sentry authentication token.")
        
        response.raise_for_status()
        issues_data = response.json()
        
        # Parse response
        issues = []
        for issue in issues_data:
            issues.append(SentryIssueListItem.from_api_response(issue))
        
        return SentryIssuesList(
            issues=issues,
            total_count=len(issues)
        )
        
    except httpx.HTTPStatusError as e:
        raise McpError(f"Error listing Sentry issues: {str(e)}")
    except Exception as e:
        raise McpError(f"An error occurred: {str(e)}")


async def serve(auth_token: str) -> Server:
    server = Server("sentry")
    http_client = httpx.AsyncClient(base_url=SENTRY_API_BASE)

    @server.list_prompts()
    async def handle_list_prompts() -> list[types.Prompt]:
        return [
            types.Prompt(
                name="sentry-issue",
                description="Retrieve a Sentry issue by ID or URL",
                arguments=[
                    types.PromptArgument(
                        name="issue_id_or_url",
                        description="Sentry issue ID or URL",
                        required=True,
                    )
                ],
            )
        ]

    @server.get_prompt()
    async def handle_get_prompt(
        name: str, arguments: dict[str, str] | None
    ) -> types.GetPromptResult:
        if name != "sentry-issue":
            raise ValueError(f"Unknown prompt: {name}")

        issue_id_or_url = (arguments or {}).get("issue_id_or_url", "")
        issue_data = await handle_sentry_issue(http_client, auth_token, issue_id_or_url)
        return issue_data.to_prompt_result()

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="get_sentry_issue",
                description="""Retrieve and analyze a Sentry issue by ID or URL. Use this tool when you need to:
                - Investigate production errors and crashes
                - Access detailed stacktraces from Sentry
                - Analyze error patterns and frequencies
                - Get information about when issues first/last occurred
                - Review error counts and status""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "issue_id_or_url": {
                            "type": "string",
                            "description": "Sentry issue ID or URL to analyze"
                        }
                    },
                    "required": ["issue_id_or_url"]
                }
            ),
            types.Tool(
                name="query_sentry_issues",
                description="""Search for Sentry issues with filters. Use this tool when you need to:
                - Find issues matching specific search terms
                - Filter issues by status (unresolved, resolved, ignored)
                - Filter issues by level (error, warning, info)
                - Find issues in a specific project
                - Get a list of issues that match certain criteria""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query to find specific issues"
                        },
                        "status": {
                            "type": "string",
                            "description": "Filter by status (unresolved, resolved, ignored)",
                            "enum": ["unresolved", "resolved", "ignored"]
                        },
                        "level": {
                            "type": "string",
                            "description": "Filter by error level (error, warning, info)",
                            "enum": ["error", "warning", "info"]
                        },
                        "project": {
                            "type": "string",
                            "description": "Filter by project identifier"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of issues to return",
                            "default": 10
                        }
                    }
                }
            ),
            types.Tool(
                name="list_latest_sentry_issues",
                description="""List the most recent Sentry issues. Use this tool when you need to:
                - Check what errors have occurred recently
                - Get a quick overview of the current error status
                - See the most recent issues without specific filtering
                - Monitor for new issues""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of issues to return",
                            "default": 10
                        }
                    }
                }
            )
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        if name == "get_sentry_issue":
            if not arguments or "issue_id_or_url" not in arguments:
                raise ValueError("Missing issue_id_or_url argument")

            issue_data = await handle_sentry_issue(http_client, auth_token, arguments["issue_id_or_url"])
            return issue_data.to_tool_result()
            
        elif name == "query_sentry_issues":
            arguments = arguments or {}
            query = arguments.get("query")
            status = arguments.get("status")
            level = arguments.get("level")
            project = arguments.get("project")
            limit = arguments.get("limit", 10)
            
            issues_list = await query_sentry_issues(
                http_client, 
                auth_token, 
                query=query, 
                status=status, 
                level=level, 
                project=project, 
                limit=limit
            )
            return issues_list.to_tool_result()
            
        elif name == "list_latest_sentry_issues":
            arguments = arguments or {}
            limit = arguments.get("limit", 10)
            
            issues_list = await list_latest_sentry_issues(
                http_client,
                auth_token,
                limit=limit
            )
            return issues_list.to_tool_result()
        
        else:
            raise ValueError(f"Unknown tool: {name}")

    return server

@click.command()
@click.option(
    "--auth-token",
    envvar="SENTRY_TOKEN",
    required=True,
    help="Sentry authentication token",
)
def main(auth_token: str):
    async def _run():
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            server = await serve(auth_token)
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="sentry",
                    server_version="0.4.1",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    asyncio.run(_run())
