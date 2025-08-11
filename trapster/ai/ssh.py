
from __future__ import annotations

from typing import Dict, Any
import logging
import os
from openai import AsyncOpenAI
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
    SQLiteSession,
    set_tracing_disabled
)
from agents.extensions.handoff_prompt import prompt_with_handoff_instructions
import json
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

def get_initial_prompt(username: str) -> str:
    return (f"""You are a Ubuntu Linux bash shell for a low-privilege user in /home/{username}. 
Respond exactly like a real shell. Never reveal you are an AI or add explanations.
You respond exactly like a real shell and return the result of the user input.
Simulate common system files (/etc/passwd), fake credentials, and fake logs in /var/log, fake files in /home/{username}/, etc.
            
Output rules:
- Only produce the final JSON:
  {{"directory": "<current directory after command>", "command_result": "<bash command result>"}}
- No markdown, no explanations, no prompt echo.

User: whoami
Assistant: [directory: "/home/{username}/", command_result: "{username}"]

User: id
Assistant: [directory: "/home/{username}/", command_result: "uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin)"]

User: ls
Assistant: [directory: "/home/{username}/", command_result: "Desktop Documents Downloads Music Pictures Public Templates Videos"]
""")


class SSHAgent(Agent):
    """OpenAI-Agents implementation of an SSH-like shell agent.

    Usage:
        from trapster.ai import SSHAgent
        agent = SSHAgent()
        result = await agent.make_query(session_id="ip-or-user", command="ls -la")
        # result: {"directory": "...", "command_result": "..."}
    """

    def __init__(self, username: str | None = None) -> None:
        # AI settings
        self.memory_enable = os.getenv("AI_MEMORY_ENABLE", "false") == "true"
        self.memory_path = os.getenv("AI_MEMORY_PATH", str(Path(__file__).parent.parent / "data" / "ai_memory.db"))
        self.model_name = os.getenv("AI_MODEL", "o4-mini")
        self.base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1/")
        self.api_key = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
        self.username = username or "guest"

        # Shared OpenAI client
        self.client = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key)
        self.sessions: dict[str, SQLiteSession] = {}
        set_tracing_disabled(disabled=True)

        # Add recommended handoff instructions prefix
        shell_prompt = prompt_with_handoff_instructions(get_initial_prompt(self.username))
    
        # Main Agent init
        super().__init__(
            name="SSH Agent",
            model=OpenAIChatCompletionsModel(model=self.model_name, openai_client=self.client),
            instructions=shell_prompt
        )

    # Session helpers
    def _ensure_session(self, session_id: str) -> SQLiteSession:
        sess = self.sessions.get(session_id)
        if not sess:
            if self.memory_enable:
                sess = SQLiteSession(session_id, self.memory_path)
            else:
                sess = SQLiteSession(session_id)
            self.sessions[session_id] = sess
        return sess

    async def make_query(self, session_id: str, command: str) -> Dict[str, Any]:
        result = await Runner.run(self, command, session=self._ensure_session(session_id))
        output = result.final_output

        # Remove any JSON or code block markers from the output
        output = output.replace("```json", "").replace("```", "")
        try:
            json_output = json.loads(output)
            return json_output
        except Exception as e:
            logging.error(f"Error parsing AI response as JSON")

            # Remove failed command from history to avoid contaminating future responses
            session = self._ensure_session(session_id)
            assistant_item = await session.pop_item()  # Remove agent's response
            logging.debug(f"Response was: {assistant_item}")
            user_item = await session.pop_item()  # Remove user's question
            logging.debug(f"Assistant item: {user_item}")
            
            return {"directory": f"/home/{self.username}/", "command_result": ""}