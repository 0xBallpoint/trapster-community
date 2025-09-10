
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Any
import os
from openai import AsyncOpenAI
from agents import (
    Agent,
    OpenAIChatCompletionsModel,
    Runner,
    SQLiteSession,
    set_tracing_disabled,
    ModelSettings,
    ModelSettings
)

from dotenv import load_dotenv
load_dotenv()

class ai_agent(Agent):
    def __init__(
        self,
        *,
        module_name: str | None = "AI Agent",
        temperature: float | None,
    ) -> None:
        

        self.memory_enable = os.getenv("AI_MEMORY_ENABLE", "false") == "true"
        memory_file_name = module_name.replace(" ", "_").lower() + "_ai_memory.db"
        self.memory_path = os.getenv("AI_MEMORY_PATH", str(Path(__file__).parent.parent / "data" / memory_file_name))
        model_name = os.getenv("AI_MODEL")  or "4o-mini"
        api_key = os.getenv("AI_API_KEY")  or os.getenv("OPENAI_API_KEY") or ""
        base_url = os.getenv("AI_BASE_URL") or "https://api.openai.com/v1/"
        temperature = temperature

        if not api_key:
            logging.error('AI_API_KEY must be set to use AI features')
            return 
        
        # Shared OpenAI client
        self.client = AsyncOpenAI(base_url=base_url, api_key=api_key)
        self.sessions: dict[str, SQLiteSession] = {}
        set_tracing_disabled(disabled=True)
        # Add recommended handoff instructions prefix
        prompt = self._get_initial_prompt()
        # Main Agent init
        super().__init__(
            name=module_name,
            model=OpenAIChatCompletionsModel(model=model_name, 
                                             openai_client=self.client), 
            model_settings=ModelSettings(temperature=temperature),
            instructions=prompt,
        )

    def _get_initial_prompt(self):
        return "be a helpful assistant"

    # Session helpers
    def _ensure_session(self, session_id: str) -> SQLiteSession:
        if not self.memory_enable:
            # if memory is disable
            return None
        
        sess = self.sessions.get(session_id)
        if not sess:
            if self.memory_path:
                sess = SQLiteSession(session_id, self.memory_path)
            else:
                sess = SQLiteSession(session_id)
            self.sessions[session_id] = sess
        return sess

    async def make_query(self, session_id: str, command: str) -> Dict[str, Any]:
        try:
            result = await Runner.run(self, command, session=self._ensure_session(session_id))
            
        except Exception as e:
            print(f"[debug] error: {e}")
            result = None
        return result
