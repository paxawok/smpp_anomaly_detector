import os
import json
import asyncio
from typing import Optional, Dict, List, Any, Union

# Виправлений імпорт
try:
    from logging.logger import default_logger
except ImportError:
    # Створюємо простий логер, якщо не можемо імпортувати
    import logging
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    class SimpleLogger:
        def __init__(self, name="redis_client"):
            self.name = name
            self.logger = logging.getLogger(name)
        
        def info(self, message, extra=None):
            self.logger.info(message)
        
        def warning(self, message, extra=None):
            self.logger.warning(message)
        
        def error(self, message, extra=None):
            self.logger.error(message)
    
    default_logger = SimpleLogger()
    
class RedisClient:
    """
    Клас-заглушка для роботи з Redis
    Використовується для тестування без підключення до Redis
    """
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
        self.storage = {}  # Internal storage for testing
        default_logger.info(f"Redis клієнт (тестовий режим): {self.url}")
    
    async def connect(self) -> None:
        # У тестовому режимі не підключаємося до Redis
        default_logger.info("Симуляція підключення до Redis (тестовий режим)")
        return
    
    async def disconnect(self) -> None:
        default_logger.info("Симуляція відключення від Redis (тестовий режим)")
        return
    
    async def _ensure_connection(self) -> None:
        # Нічого не робимо у тестовому режимі
        return
    
    # Базові операції
    async def get(self, key: str) -> Any:
        await self._ensure_connection()
        return self.storage.get(key)
    
    async def set(self, key: str, value: str, expire: Optional[int] = None) -> bool:
        await self._ensure_connection()
        self.storage[key] = value
        return True
    
    async def delete(self, key: str) -> int:
        await self._ensure_connection()
        if key in self.storage:
            del self.storage[key]
            return 1
        return 0
    
    async def incr(self, key: str) -> int:
        await self._ensure_connection()
        if key not in self.storage:
            self.storage[key] = "1"
            return 1
        try:
            value = int(self.storage[key]) + 1
            self.storage[key] = str(value)
            return value
        except (ValueError, TypeError):
            self.storage[key] = "1"
            return 1
    
    async def expire(self, key: str, seconds: int) -> bool:
        await self._ensure_connection()
        # У тестовому режимі нічого не робимо
        return True
    
    # Додаткові методи, які можуть знадобитися
    async def check_rate_limit(self, source_addr: str, destination_addr: str) -> Dict[str, Any]:
        """
        Перевіряє обмеження швидкості для відправника і отримувача
        """
        key = f"rate_limit:{source_addr}:{destination_addr}"
        count = await self.incr(key)
        
        # У тестовому режимі просто повертаємо результат
        return {
            "exceeded": count > 100,  # Для тестування використовуємо високе значення
            "count": count,
            "limit": 100,
            "risk_score": 0.1 * min(count / 10, 1.0)
        }