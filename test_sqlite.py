#!/usr/bin/env python
# test_sqlite.py

import asyncio
import sys
import os

# Додаємо батьківський каталог до шляху для імпорту
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from storage.sqlite_client import SQLiteClient

async def main():
    print("Тестування SQLite клієнта...")
    client = SQLiteClient()
    
    try:
        # Підключаємось до бази даних
        await client.connect()
        print("✓ Підключено до SQLite")
        
        # Базові операції
        await client.set('test_key', 'test_value')
        print("✓ Записано тестове значення")
        
        value = await client.get('test_key')
        print(f"✓ Зчитане значення: {value}")
        
        # Тестуємо інкремент
        await client.set('counter', '10')
        new_value = await client.incr('counter')
        print(f"✓ Інкремент лічильника: {new_value}")
        
        # Тестуємо видалення
        await client.delete('test_key')
        print("✓ Видалено тестовий ключ")
        
        # Тестуємо rate limiter
        result = await client.check_rate_limit('sender1', 'recipient1', daily_limit=5)
        print(f"✓ Результат перевірки rate limit: {result}")
        
        # Тестуємо blacklist
        await client.add_to_blacklist('malicious.com', 'domain')
        blacklist_check = await client.check_blacklist('malicious.com', 'domain')
        print(f"✓ Результат перевірки blacklist: {blacklist_check}")
        
        # Тестуємо запис аномалії
        anomaly_data = {
            "source": "TestSender",
            "dest": "TestRecipient",
            "message": "Test message",
            "risk_score": 0.8,
            "decision": "suspicious",
            "tags": ["test", "simulation"]
        }
        await client.record_anomaly(anomaly_data)
        print("✓ Аномалія записана")
        
        # Тестуємо отримання аномалій
        anomalies = await client.get_recent_anomalies(limit=5)
        print(f"✓ Отримано {len(anomalies)} останніх аномалій")
        
        # Загальна статистика
        stats = await client.get_stats()
        print(f"✓ Статистика: {stats}")
        
        # Відключаємось
        await client.disconnect()
        
        print("\n✅ SQLite клієнт працює успішно!")
        
    except Exception as e:
        print(f"\n❌ Помилка: {e}")
        
        # Відключаємось
        try:
            await client.disconnect()
        except:
            pass

if __name__ == "__main__":
    asyncio.run(main())