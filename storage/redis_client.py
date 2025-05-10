import aioredis
import os
import json
from typing import Optional, Dict, List, Any, Union

from logging.logger import default_logger

class RedisClient:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: int = 0,
    ):
        self.host = host or os.environ.get("REDIS_HOST", "localhost")
        self.port = port or int(os.environ.get("REDIS_PORT", 6379))
        self.db = db
        self.redis = None
        self.url = f"Redis://{self.host}:{self.port}/{self.db}"
        default_logger.info(f"Redis клієнт: {self.url}")
    
    async def connect(self) -> None:
        if self.redis is None:
            try:
                self.redis = await aioredis.from_url(
                    self.url,
                    encoding="utf-8",
                    decode_responses=True
                )
                default_logger.info(f"Підключено до Redis: {self.url}")
            except Exception as e:
                default_logger.error(f"Помилка підключення до Redis: {e}")
                raise
    
    async def disconnect(self) -> None:
        if self.redis is not None:
            await self.redis.close()
            self.redis = None
            default_logger.info("Відключено від Redis")
    
    async def _ensure_connection(self) -> None:
        if self.redis is None:
            await self.connect()
    
    # базові операції
    async def get(self, key: str) -> Any:
        await self._ensure_connection()
        return await self.redis.get(key)
    
    async def set(self, key: str, value: str, expire: Optional[int] = None) -> bool:
        await self._ensure_connection()
        await self.redis.set(key, value)
        if expire is not None:
            await self.redis.expire(key, expire)
        return True
    
    async def delete(self, key: str) -> int:
        await self._ensure_connection()
        return await self.redis.delete(key)
    
    async def incr(self, key: str) -> int:
        await self._ensure_connection()
        return await self.redis.incr(key)
    
    async def expire(self, key: str, seconds: int) -> bool:
        await self._ensure_connection()
        return await self.redis.expire(key, seconds)