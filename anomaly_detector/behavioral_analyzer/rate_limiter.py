import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Tuple


class RateLimiter:
    """
    Клас для обмеження кількості SMS-повідомлень, надісланих на один номер телефону за день.
    
    Attributes:
        daily_limit (int): Максимальна кількість повідомлень на день.
        counters (Dict[str, Tuple[int, float]]): Словник лічильників для кожного номера.
                 Формат: {номер: (кількість, timestamp останнього оновлення)}
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
        self.counters: Dict[str, Tuple[int, float]] = {}
        self.cleanup_interval = cleanup_interval
        self.lock = threading.RLock()
        
        # Запускаємо фоновий потік для очищення застарілих лічильників
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self) -> None:
        """Запускає фоновий потік для очищення застарілих лічильників."""
        
        def cleanup_task():
            while True:
                time.sleep(self.cleanup_interval)
                self._cleanup_expired_counters()
        
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_counters(self) -> None:
        """Очищає застарілі лічильники (старші за 24 години)."""
        current_time = time.time()
        day_seconds = 24 * 60 * 60  # 24 години в секундах
        
        with self.lock:
            # Створюємо список номерів для видалення
            to_remove = []
            
            for number, (count, last_update) in self.counters.items():
                # Якщо минуло більше 24 годин з моменту останнього оновлення
                if current_time - last_update > day_seconds:
                    to_remove.append(number)
            
            # Видаляємо застарілі лічильники
            for number in to_remove:
                del self.counters[number]
    
    def increment(self, destination_number: str) -> int:
        """
        Збільшує лічильник для вказаного номера.
        
        Args:
            destination_number: Номер телефону одержувача.
            
        Returns:
            int: Нове значення лічильника.
        """
        with self.lock:
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
    
    def is_allowed(self, destination_number: str) -> bool:
        """
        Перевіряє, чи дозволено надсилати SMS на вказаний номер.
        
        Args:
            destination_number: Номер телефону одержувача.
            
        Returns:
            bool: True, якщо надсилання дозволено, False - якщо ліміт вичерпано.
        """
        with self.lock:
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
    
    def get_count(self, destination_number: str) -> int:
        """
        Повертає поточне значення лічильника для вказаного номера.
        
        Args:
            destination_number: Номер телефону одержувача.
            
        Returns:
            int: Поточне значення лічильника або 0, якщо номер відсутній.
        """
        with self.lock:
            if destination_number in self.counters:
                count, last_update = self.counters[destination_number]
                current_time = time.time()
                
                # Якщо лічильник застарів, повертаємо 0
                if current_time - last_update > 24 * 60 * 60:
                    return 0
                
                return count
            
            return 0
    
    def reset(self, destination_number: str = None) -> None:
        """
        Скидає лічильник для вказаного номера або всі лічильники.
        
        Args:
            destination_number: Номер телефону одержувача. Якщо None, скидаються всі лічильники.
        """
        with self.lock:
            if destination_number:
                if destination_number in self.counters:
                    del self.counters[destination_number]
            else:
                self.counters.clear()


# Створюємо глобальний екземпляр для використання в різних модулях
rate_limiter = RateLimiter()


# Приклад використання
if __name__ == "__main__":
    # Приклад використання класу
    limiter = RateLimiter(daily_limit=5)  # Для тестування зменшуємо ліміт до 5
    
    # Симулюємо надсилання SMS
    test_number = "+380671234567"
    
    for i in range(7):
        if limiter.is_allowed(test_number):
            print(f"SMS #{i+1} дозволено відправити на {test_number}")
            count = limiter.increment(test_number)
            print(f"Лічильник для {test_number}: {count}")
        else:
            print(f"SMS #{i+1} заборонено відправити на {test_number} (ліміт вичерпано)")
    
    print("\nЗагальний стан лічильників:")
    print(limiter.counters)
    
    print("\nСкидаємо лічильник для тестового номера:")
    limiter.reset(test_number)
    print(f"Лічильник після скидання: {limiter.get_count(test_number)}")
    
    print("\nПеревіряємо дозвіл після скидання:")
    if limiter.is_allowed(test_number):
        print(f"SMS дозволено відправити на {test_number}")
    else:
        print(f"SMS заборонено відправити на {test_number}")
