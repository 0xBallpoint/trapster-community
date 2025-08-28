
from __future__ import annotations

from typing import Dict, Any
import logging
import json
from agents import (
    Runner,
    SQLiteSession,
)

from trapster.ai.base import ai_agent

def _get_initial_prompt(username: str) -> str:
    return (f"""You are a Ubuntu Linux bash shell for a low-privilege user in /home/{username}. 
Respond exactly like a real shell. Never reveal you are an AI or add explanations.
You respond exactly like a real shell and return the result of the user input.
Simulate common system files (/etc/passwd), fake credentials, and fake logs in /var/log, fake files in /home/{username}/, etc.
            
Output rules:
- Only produce the final JSON:
  {{"directory": "<current directory after command>", "command_result": "<bash command result>"}}
- No markdown, no explanations, no prompt echo.

User: whoami
Assistant: {{"directory": "/home/{username}/", "command_result": "{username}"}}

User: id
Assistant: {{"directory": "/home/{username}/", "command_result": "uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin)"}}

User: ls
Assistant: {{"directory": "/home/{username}/", "command_result": "Desktop Documents Downloads Music Pictures Public Templates Videos"}}
""")


class SSHAgent(ai_agent):
    """OpenAI-Agents implementation of an SSH-like shell agent.

    Usage:
        from trapster.ai import SSHAgent
        agent = SSHAgent()
        result = await agent.make_query(session_id="ip-or-user", command="ls -la")
        # result: {"directory": "...", "command_result": "..."}
    """
    def __init__(
        self,
        *,
        model_name: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        memory_path: str | None = None,
        custom_ai_prompt: str | None = None,
        temperature: float | None = None,
    ) -> None:
        super().__init__(
            model_name=model_name,
            module_name="SSH Agent",
            api_key=api_key,
            base_url=base_url,
            memory_path=memory_path,
            custom_ai_prompt=custom_ai_prompt,
            temperature=temperature,
        )
   
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