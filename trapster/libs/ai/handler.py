import logging
import httpx
from abc import ABC, abstractmethod

from .redis_manager import RedisManager

class HandlerAI(ABC):
    def __init__(self, 
                 api_url="https://llama-3-1-70b-instruct.endpoints.kepler.ai.cloud.ovh.net/api/openai_compat/v1/chat/completions", 
                 api_key=None, 
                 headers=None):
        
        self.MAX_HISTORY_MESSAGES = 50
        self.url = api_url
        self.api_key = api_key
        self.headers = headers or {
            "Content-Type": "application/json",
            #"Authorization": f"Bearer {self.api_key}"
        }
        self.redis_manager = RedisManager()
        self.initial_messages = self._get_initial_messages()

    @abstractmethod
    def _get_initial_messages(self) -> list:
        """
        Each AI handler should define its own initial messages
        It should contains the system prompt and the initial user message
        """
        pass

    async def make_query(self, session_id: str, prompt: str) -> str:
        """
        Make a query to the AI API
        A session is a unique identifier for a user's interaction with the AI (IP, username, etc.)
        """

        # Connect to Redis
        await self.redis_manager.connect()

        # Get existing messages for this session
        messages = await self.redis_manager.get_history(session_id)
        messages = self.initial_messages + messages[:self.MAX_HISTORY_MESSAGES]

        # Add new message
        new_message = {
            "content": prompt,
            "name": "user",
            "role": "user"
        }

        # Check cache first
        cached_response = await self.redis_manager.get_cache(prompt)
        if cached_response is not None:
            # Add both the user message and cached response to history
            await self.redis_manager.add_to_history(session_id, new_message)
            await self.redis_manager.add_to_history(session_id, {
                "content": cached_response,
                "name": "assistant",
                "role": "assistant"
            })
            return cached_response
        
        # If not in cache, proceed with API call
        await self.redis_manager.add_to_history(session_id, new_message)

        payload = {
            "max_tokens": 3000,
            "messages": messages + [new_message],
            "model": "Meta-Llama-3_1-70B-Instruct",
            "temperature": 0,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.url, json=payload, headers=self.headers)
                logging.debug(response.text)
        except httpx.RequestError as e:
            logging.error(f"RequestError: {e}")
            return ""

        if response.status_code == 200:
            response_data = response.json()    
            choices = response_data["choices"]
            
            for choice in choices:
                result = choice["message"]["content"]
                
                # Save assistant's response to history
                await self.redis_manager.add_to_history(session_id, {
                    "content": result,
                    "name": "assistant",
                    "role": "assistant"
                })
                
                # Save to cache
                await self.redis_manager.set_cache(prompt, result)
                
                return result
        else:
            logging.error("Error:", response.text)
            return ""