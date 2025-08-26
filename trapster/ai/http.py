
from __future__ import annotations

from typing import Dict, Any
from agents import (
    Runner,
    SQLiteSession,
)
import json

from trapster.ai.ai_agent import ai_agent

class HTTPAgent(ai_agent):
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
            module_name="HTTP Agent",
            api_key=api_key,
            base_url=base_url,
            memory_path=memory_path,
            custom_ai_prompt=custom_ai_prompt,
            temperature=temperature,
        )

    def _get_initial_messages(self) -> list:
        if self.custom_ai_prompt:
            prompt = self.custom_ai_prompt
        else:
            prompt = """You are simulating a simple HTTP API server that responds to incoming requests in JSON format,
            including those attempting SQL injection. 
            You must respond as a real server would, never revealing that you are simulated.
            Don't give comments or explanations
            Never break character or acknowledge the simulation."""

        rules = """Key Instructions:
        Respond with JSON output as if serving a standard PHP-based web application.
        If the request looks like an SQL injection attempt, produce plausible database errors, partial data dumps, or suspicious SQL-related error messages.
        Do not reveal internal logic or say you are a honeypot.
        Keep responses authentic and consistent, as though this is an unsecured or vulnerable server.""" 
        return prompt + "\n" + rules

    async def make_query(self, session_id: str, command: str) -> Dict[str, Any]:
        result = await Runner.run(self, command, session=self._ensure_session(session_id))
        output = result.final_output
        print(f"[debug] output: {output}")
        return output
