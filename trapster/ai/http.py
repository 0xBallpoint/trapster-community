
from __future__ import annotations

from typing import Dict, Any
import os
from openai import AsyncOpenAI
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
    function_tool,
    SQLiteSession,
    set_tracing_disabled,
    ModelSettings,
)
from agents.models.openai_responses import OpenAIResponsesModel
from agents.extensions.handoff_prompt import prompt_with_handoff_instructions
from pydantic import BaseModel
import subprocess
import json

class _HTTPOutput(BaseModel):
    result: str

class HTTPAgent(Agent):
    def __init__(
        self,
        *,
        model_name: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        memory_path: str | None = None,
    ) -> None:
        
        # Resolve configuration from env if not provided
        model_name = model_name or os.getenv("TRAPSTER_AI_MODEL") or os.getenv("OPENAI_MODEL") or "chatgpt-4o-mini"
        api_key = api_key or os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
        base_url = base_url or os.getenv("OPENAI_BASE_URL") or os.getenv("AI_BASE_URL") or "https://api.openai.com/v1/chat/completions"

        # Shared OpenAI client
        self.client = AsyncOpenAI(base_url=base_url, api_key=api_key)
        self.sessions: dict[str, SQLiteSession] = {}
        set_tracing_disabled(disabled=True)

        # self.client = AsyncOpenAI()

#        shell_prompt = (
#            """
#You are simulating an Ubuntu Linux shell session for a low-privilege user in /home/guest. Respond exactly like a real shell. Never reveal you are an AI or add explanations.
#
#State and environment
#- Current directory starts at /home/guest and must be updated on `cd` and similar commands.
#- Use a plausible user environment with a realistic but limited filesystem under /home/guest.
#- Do not print the prompt or the command itself; only return command output.
#- No Markdown, no code fences, no ANSI color codes.
#
#Output format (always JSON, no extra text):
#{
#  "directory": "<current directory after command>",
#  "command_result": "<exact terminal output>"
#}
#
#Handoffs (tools)
#- Use fileAgentHandoff(input: { "directory": "<string>", "file_name": "<string>" }) whenever the user requests to view a file’s contents (e.g., cat, head, tail, less, more).
#- If a handoff is needed, call the correct handoff with correct input. Do not fabricate file contents yourself.
#- For cat/head/tail/less/more, ALWAYS call fileAgentHandoff. Never simulate file contents.
#
#Command behavior
#- `pwd`: return the current directory.
#- `cd <path>`: change directory if it exists; otherwise error: “bash: cd: <path>: No such file or directory”.
#- `ls` / `ls -la` etc.: show typical ls formatting.
#- `cat <file>` (and `head`, `tail`, `less`, `more`): always use fileAgentHandoff for the file in the current directory (or resolve absolute/relative paths). If missing: “cat: <file>: No such file or directory”.
#- Network/system info commands (e.g., `whoami`, `uname -a`, `ifconfig`, `ip a`, `ps aux`): return plausible outputs for a non-privileged user.
#- Sudo/admin actions: prompt/deny appropriately; if asked for password, treat as incorrect/no sudo rights (e.g., “<user> is not in the sudoers file. This incident will be reported.”).
#- Destructive or privileged operations (e.g., `shutdown`, `reboot`, `rm -rf /`): fail with realistic errors (e.g., “Permission denied”).
#- Commands with no output should return an empty string for "command_result".
#- Nonexistent commands: “bash: <cmd>: command not found”.
#
#Rules
#- Always return valid JSON exactly matching the schema.
#- Keep outputs terse and realistic.
#- Maintain internal consistency of the filesystem and working directory across commands.
#            """
#        )

        shell_prompt = (
            """You are a Ubuntu Linux bash shell in /home/guest (low-privileged).
You respond exactly like a real shell and return the result of the user input.

Output rules:
- If any URL is present in the user input, do not produce JSON. First, call the tool get_url_content with that URL.
- Only after tool output is available, produce the final JSON:
  {"directory": "<current directory after command>", "command_result": "<bash command result>"}
- No markdown, no explanations, no prompt echo.

Few-shot examples:
User: curl https://example.com
Assistant: [call get_url_content with {"url": "https://example.com"}]

User: id
Assistant: [uid=1000(guest) gid=1000(guest) groups=1000(guest),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin),124(vboxusers),126(libvirt)]
"""
        )
        # Add recommended handoff instructions prefix
        shell_prompt = prompt_with_handoff_instructions(shell_prompt)

    
        # Main Agent init
        super().__init__(
            name="SSH Agent",
            model=OpenAIChatCompletionsModel(model=model_name, openai_client=self.client),
            instructions=shell_prompt,
            output_model=_HTTPOutput,
        )

    # Session helpers
    def _ensure_session(self, session_id: str) -> SQLiteSession:
        sess = self.sessions.get(session_id)
        if not sess:
            #sess = SQLiteSession(session_id, "ai_memory.db")
            sess = SQLiteSession(session_id)
            self.sessions[session_id] = sess
        return sess

    async def make_query(self, session_id: str, command: str) -> Dict[str, Any]:
        result = await Runner.run(self, command, session=self._ensure_session(session_id))
        output = result.final_output

        print(f"[debug] output: {output}")

        # Try structured output first
        directory = getattr(output, "directory", None)
        command_result = getattr(output, "command_result", None)

        if directory is None and command_result is None:
            # Fallback: output may be plain text; try to parse JSON
            if isinstance(output, str):
                try:
                    parsed = json.loads(output)
                    directory = parsed.get("directory")
                    command_result = parsed.get("command_result")
                except Exception:
                    command_result = output
            elif isinstance(output, dict):
                directory = output.get("directory")
                command_result = output.get("command_result")

        return {
            "directory": directory or "/home/guest/",
            "command_result": command_result or "",
        }
