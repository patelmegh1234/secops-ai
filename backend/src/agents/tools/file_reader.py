"""
CrewAI tool: Fetches file contents from GitHub via the REST API.
Used by the triage and patch agents to read vulnerable code.
"""

import base64
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from src.core.config import get_settings
from src.core.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


class FileReaderInput(BaseModel):
    owner: str = Field(description="GitHub repository owner (user or org)")
    repo: str = Field(description="GitHub repository name")
    path: str = Field(description="File path within the repository (e.g. 'src/auth.py')")
    ref: str = Field(default="main", description="Branch, tag, or commit SHA")
    start_line: int | None = Field(default=None, description="Optional start line to extract")
    end_line: int | None = Field(default=None, description="Optional end line to extract")


class GitHubFileReaderTool(BaseTool):
    name: str = "github_file_reader"
    description: str = (
        "Fetches the content of a specific file from a GitHub repository. "
        "Can optionally extract a line range. "
        "Returns the raw file content as a string."
    )
    args_schema: type[BaseModel] = FileReaderInput

    def _run(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str = "main",
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> str:
        """Synchronous wrapper for the async GitHub file fetch."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self._fetch_file(owner, repo, path, ref, start_line, end_line)
        )

    async def _fetch_file(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
        start_line: int | None,
        end_line: int | None,
    ) -> str:
        import httpx

        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        headers = {
            "Authorization": f"token {settings.github_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        params = {"ref": ref}

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()

        data = response.json()

        if isinstance(data, list):
            # Path is a directory, not a file
            return f"[ERROR] Path {path} is a directory, not a file."

        if data.get("encoding") != "base64":
            return f"[ERROR] Unexpected encoding: {data.get('encoding')}"

        content_bytes = base64.b64decode(data["content"])
        content = content_bytes.decode("utf-8", errors="replace")

        if start_line is not None or end_line is not None:
            lines = content.splitlines()
            s = (start_line or 1) - 1
            e = end_line or len(lines)
            # Add context: 5 lines before and after
            context_start = max(0, s - 5)
            context_end = min(len(lines), e + 5)
            selected_lines = lines[context_start:context_end]

            # Annotate line numbers
            annotated = []
            for i, line in enumerate(selected_lines, start=context_start + 1):
                marker = ">>>" if s + 1 <= i <= e else "   "
                annotated.append(f"{marker} {i:4d} | {line}")

            return "\n".join(annotated)

        return content

    async def _arun(self, **kwargs: Any) -> str:
        return self._run(**kwargs)
