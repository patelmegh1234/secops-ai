"""
CrewAI tool: Generates unified diffs between original and patched code.
Used by the patch agent to produce clean, reviewable diffs.
"""

import difflib
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class DiffGeneratorInput(BaseModel):
    original_code: str = Field(description="The original (vulnerable) code")
    patched_code: str = Field(description="The patched (fixed) code")
    filename: str = Field(default="file.py", description="Filename for the diff header")


class UnifiedDiffTool(BaseTool):
    name: str = "unified_diff_generator"
    description: str = (
        "Generates a unified diff between original and patched code. "
        "Returns the diff as a string in standard unified diff format. "
        "Use this after generating a patch to produce a reviewable diff."
    )
    args_schema: type[BaseModel] = DiffGeneratorInput

    def _run(
        self,
        original_code: str,
        patched_code: str,
        filename: str = "file.py",
    ) -> str:
        original_lines = original_code.splitlines(keepends=True)
        patched_lines = patched_code.splitlines(keepends=True)

        diff = list(
            difflib.unified_diff(
                original_lines,
                patched_lines,
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
                lineterm="",
                n=3,  # 3 lines of context
            )
        )

        if not diff:
            return "No changes detected between original and patched code."

        return "\n".join(diff)

    async def _arun(self, **kwargs: Any) -> str:
        return self._run(**kwargs)


def generate_diff(original: str, patched: str, filename: str = "file.py") -> str:
    """Standalone utility function for generating diffs outside CrewAI context."""
    tool = UnifiedDiffTool()
    return tool._run(original_code=original, patched_code=patched, filename=filename)
