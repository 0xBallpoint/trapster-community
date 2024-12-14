from redis import asyncio as aioredis
import json
import hashlib
from typing import List, Dict

class RedisManager:
    def __init__(self, host="localhost", port=6379, history_expiration=None, cache_expiration=3600):
        self.redis = None
        self.host = host
        self.port = port
        self.history_expiration = history_expiration # Purge history after expiration
        self.cache_expiration = cache_expiration # Purge cache after expiration

    async def connect(self):
        self.redis = await aioredis.from_url(
            f"redis://{self.host}:{self.port}",
            decode_responses=True  # This will automatically decode responses to strings
        )

    async def get_history(self, session_id: str) -> List[Dict]:
        history = await self.redis.get(f"history:{session_id}")
        if history:
            return json.loads(history)
        return []

    async def add_to_history(self, session_id: str, messages: Dict):
        history = await self.get_history(session_id)
        history.append(messages)
        await self.redis.set(f"history:{session_id}", json.dumps(history), ex=self.history_expiration)

    async def get_cache(self, user_message: str) -> str:
        key = self._generate_key(user_message)
        return await self.redis.get(f"cache:{key}")

    async def set_cache(self, user_message: str, response: str):
        key = self._generate_key(user_message)
        await self.redis.set(f"cache:{key}", response, ex=self.cache_expiration)

    def _generate_key(self, message: str) -> str:
        return hashlib.sha256(message.encode()).hexdigest()