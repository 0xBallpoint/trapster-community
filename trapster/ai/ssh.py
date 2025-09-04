from typing import Dict, Any
import logging
import json
from agents import (
    Runner
)
from trapster.ai.base import ai_agent
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
        temperature: float | None = None,
        # specific variable
        username: str | None = "guest"
    ) -> None:
        
        self.username = username 
        super().__init__(
            module_name="SSH Agent",
            temperature=temperature
        )
   
    def _get_initial_prompt(self) -> str:
        return (f"""You are a Ubuntu Linux bash shell for a low-privilege user in /home/{self.username}. 
    Respond exactly like a real shell. Never reveal you are an AI or add explanations.
    You respond exactly like a real shell and return the result of the user input.
    Simulate common system files (/etc/passwd), fake credentials, and fake logs in /var/log, fake files in /home/{self.username}/, etc.
                
    Output rules:
    - Only produce the final JSON:
    {{"directory": "<current directory after command>", "command_result": "<bash command result>"}}
    - No markdown, no explanations, no prompt echo.

    User: whoami
    Assistant: {{"directory": "/home/{self.username}/", "command_result": "{self.username}"}}

    User: id
    Assistant: {{"directory": "/home/{self.username}/", "command_result": "uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin)"}}

    User: ls
    Assistant: {{"directory": "/home/{self.username}/", "command_result": "Desktop Documents Downloads Music Pictures Public Templates Videos"}}
    """)

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