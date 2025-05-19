import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any

from logger.logger import SMPPLogger
from storage.sqlite_client import SQLiteClient

logger = SMPPLogger("rate_limiter")

class RateLimiter:
    """
    Клас для обмеження кількості SMS-повідомлень, надісланих на один номер телефону за день.
    Використовує SQLite для зберігання лічильників.
    
    Attributes:
        daily_limit (int): Максимальна кількість повідомлень на день.
        sqlite_client (SQLiteClient): Клієнт для роботи з SQLite.
        cleanup_interval (int): Інтервал очищення застарілих лічильників (в секундах).
    """
    
    def __init__(self, daily_limit: int = 30, cleanup_interval: int = 3600):
        """
        Ініціалізує обмежувач частоти з вказаними параметрами.
        
        Args:
            daily_limit: Максимальна кількість повідомлень на день.
            cleanup_interval: Інтервал очищення лічильників (в секундах).
        """
        self.daily_limit = daily_limit
        self.cleanup_interval = cleanup_interval
        self.sqlite_client = SQLiteClient()
        
        # Лічильник для роботи в випадку, коли SQLite недоступний
        self.counters: Dict[str, Tuple[int, float]] = {}
        self.lock = asyncio.Lock()
        
        logger.info(f"RateLimiter ініціалізовано з лімітом {daily_limit} повідомлень на день")
    
    async def init(self) -> None:
        """Ініціалізує підключення до SQLite"""
        await self.sqlite_client.connect()
        # Запускаємо фоновий потік для очищення застарілих лічильників
        asyncio.create_task(self._cleanup_task())
    
    async def _cleanup_task(self) -> None:
        """Фоновий потік для очищення застарілих лічильників"""
        while True:
            await asyncio.sleep(self.cleanup_interval)
            await self._cleanup_expired_counters()
    
    async def _cleanup_expired_counters(self) -> None:
        """Очищає застарілі лічильники (старші за 24 години)."""
        # В SQLite це не потрібно, оскільки ми встановлюємо TTL при створенні ключів
        # Але підтримуємо для локального режиму
        current_time = time.time()
        day_seconds = 24 * 60 * 60  # 24 години в секундах
        
        async with self.lock:
            # Створюємо список номерів для видалення
            to_remove = []
            
            for number, (count, last_update) in self.counters.items():
                # Якщо минуло більше 24 годин з моменту останнього оновлення
                if current_time - last_update > day_seconds:
                    to_remove.append(number)
            
            # Видаляємо застарілі лічильники
            for number in to_remove:
                del self.counters[number]
    
    async def increment(self, destination_number: str) -> int:
        """
        Збільшує лічильник для вказаного номера.
        
        Args:
            destination_number: Номер телефону одержувача.
            
        Returns:
            int: Нове значення лічильника.
        """
        try:
            # Спочатку спробуємо використати SQLite
            key = f"rate_limit:{destination_number}"
            count = await self.sqlite_client.incr(key)
            
            # При першому інкременті встановлюємо TTL на 24 години
            if count == 1:
                await self.sqlite_client.set(key, str(count), 24 * 60 * 60)
            
            return count
            
        except Exception as e:
            logger.warning(f"Помилка при використанні SQLite, використовується локальний лічильник: {e}")
            
            # Fallback на локальний лічильник
            async with self.lock:
                current_time = time.time()
                
                if destination_number in self.counters:
                    count, last_update = self.counters[destination_number]
                    
                    # Перевіряємо, чи не застарів лічильник (більше 24 годин)
                    if current_time - last_update > 24 * 60 * 60:
                        # Якщо застарів, скидаємо його
                        count = 1
                    else:
                        # Інакше збільшуємо
                        count += 1
                else:
                    # Ініціалізуємо новий лічильник
                    count = 1
                
                # Оновлюємо лічильник і час останнього оновлення
                self.counters[destination_number] = (count, current_time)
                
                return count
    
    async def is_allowed(self, destination_number: str) -> bool:
        """
        Перевіряє, чи дозволено надсилати SMS на вказаний номер.
        
        Args:
            destination_number: Номер телефону одержувача.
            
        Returns:
            bool: True, якщо надсилання дозволено, False - якщо ліміт вичерпано.
        """
        try:
            # Спочатку спробуємо використати SQLite
            key = f"rate_limit:{destination_number}"
            count_str = await self.sqlite_client.get(key)
            
            if count_str:
                count = int(count_str)
                return count < self.daily_limit
            
            return True  # Якщо ключа немає, значить лічильник не використовувався
            
        except Exception as e:
            logger.warning(f"Помилка при використанні SQLite, використовується локальний лічильник: {e}")
            
            # Fallback на локальний лічильник
            async with self.lock:
                # Якщо номер відсутній в лічильниках, значить дозволено
                if destination_number not in self.counters:
                    return True
                
                count, last_update = self.counters[destination_number]
                current_time = time.time()
                
                # Якщо лічильник застарів (більше 24 годин), дозволяємо
                if current_time - last_update > 24 * 60 * 60:
                    return True
                
                # Перевіряємо, чи не перевищено ліміт
                return count < self.daily_limit
    
    async def get_count(self, destination_number: str) -> int:
        """
        Повертає поточне значення лічильника для вказаного номера.
        
        Args:
            destination_number: Номер телефону одержувача.
            
        Returns:
            int: Поточне значення лічильника або 0, якщо номер відсутній.
        """
        try:
            # Спочатку спробуємо використати SQLite
            key = f"rate_limit:{destination_number}"
            count_str = await self.sqlite_client.get(key)
            
            if count_str:
                return int(count_str)
            
            return 0  # Якщо ключа немає, значить лічильник не використовувався
            
        except Exception as e:
            logger.warning(f"Помилка при використанні SQLite, використовується локальний лічильник: {e}")
            
            # Fallback на локальний лічильник
            async with self.lock:
                if destination_number in self.counters:
                    count, last_update = self.counters[destination_number]
                    current_time = time.time()
                    
                    # Якщо лічильник застарів, повертаємо 0
                    if current_time - last_update > 24 * 60 * 60:
                        return 0
                    
                    return count
                
                return 0
    
    async def check_rate_limit(self, source_addr: str, destination_addr: str) -> Dict[str, Any]:
        """
        Перевіряє обмеження частоти для відправника та отримувача
        
        Args:
            source_addr: Адреса відправника
            destination_addr: Адреса отримувача
            
        Returns:
            Dict[str, Any]: Результат перевірки у форматі
                        {"exceeded": bool, "count": int, "limit": int, "risk_score": float}
        """
        try:
            # Використовуємо SQLite для перевірки обмеження
            return await self.sqlite_client.check_rate_limit(
                source_addr, destination_addr, daily_limit=self.daily_limit
            )
        except Exception as e:
            logger.warning(f"Помилка при використанні SQLite, використовується локальний лічильник: {e}")
            
            # Використовуємо локальний лічильник
            count = await self.get_count(destination_addr)
            new_count = await self.increment(destination_addr)
            
            # Визначаємо, чи перевищено ліміт
            exceeded = new_count > self.daily_limit
            
            # Обчислюємо оцінку ризику на основі відношення до ліміту
            risk_score = min(1.0, new_count / self.daily_limit * 0.8)
            
            return {
                "exceeded": exceeded,
                "count": new_count,
                "limit": self.daily_limit,
                "risk_score": risk_score
            }
    
    async def reset(self, destination_number: str = None) -> None:
        """
        Скидає лічильник для вказаного номера або всі лічильники.
        
        Args:
            destination_number: Номер телефону одержувача. Якщо None, скидаються всі лічильники.
        """
        try:
            # Спочатку спробуємо використати SQLite
            if destination_number:
                key = f"rate_limit:{destination_number}"
                await self.sqlite_client.delete(key)
            else:
                # Небезпечно видаляти всі ключі, тому цю операцію не реалізуємо
                # для SQLite у виробничому середовищі
                pass
                
        except Exception as e:
            logger.warning(f"Помилка при використанні SQLite, використовується локальний лічильник: {e}")
            
            # Fallback на локальний лічильник
            async with self.lock:
                if destination_number:
                    if destination_number in self.counters:
                        del self.counters[destination_number]
                else:
                    self.counters.clear()


# Створюємо глобальний екземпляр для використання в різних модулях
rate_limiter = RateLimiter()

# Функція для ініціалізації глобального екземпляра
async def init_rate_limiter() -> None:
    await rate_limiter.init()


# Приклад використання
if __name__ == "__main__":
    async def test_rate_limiter():
        # Ініціалізуємо RateLimiter
        limiter = RateLimiter(daily_limit=5)  # Для тестування зменшуємо ліміт до 5
        await limiter.init()
        
        # Симулюємо надсилання SMS
        test_number = "+380671234567"
        
        for i in range(7):
            allowed = await limiter.is_allowed(test_number)
            if allowed:
                print(f"SMS #{i+1} дозволено відправити на {test_number}")
                count = await limiter.increment(test_number)
                print(f"Лічильник для {test_number}: {count}")
            else:
                print(f"SMS #{i+1} заблоковано для {test_number} (ліміт вичерпано)")
        
        print("\nЗагальний стан лічильників:")
        print(f"SQLite count: {await limiter.get_count(test_number)}")
        
        print("\nСкидаємо лічильник для тестового номера:")
        await limiter.reset(test_number)
        print(f"Лічильник після скидання: {await limiter.get_count(test_number)}")
        
        print("\nПеревіряємо дозвіл після скидання:")
        if await limiter.is_allowed(test_number):
            print(f"SMS дозволено відправити на {test_number}")
        else:
            print(f"SMS заблоковано для {test_number}")
    
    # Запускаємо тест
    asyncio.run(test_rate_limiter())