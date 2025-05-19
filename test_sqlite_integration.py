import asyncio
import os
import sys
import json

# Додаємо батьківський каталог до шляху для імпорту
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from storage.sqlite_client import SQLiteClient
from anomaly_detector.behavioral_analyzer.rate_limiter import RateLimiter
from anomaly_detector.signature_analyzer.blacklists import BlacklistsAnalyzer

async def test_sqlite():
    print("=== Тестування інтеграції з SQLite ===")
    
    # Шлях до бази даних
    db_path = "./storage/custom_db.db"
    print(f"Використовуємо базу даних: {db_path}")
    
    # Перевіряємо існування файлу бази даних
    if os.path.exists(db_path):
        print(f"✅ Файл бази даних існує: {db_path}")
        file_size = os.path.getsize(db_path)
        print(f"   Розмір файлу: {file_size} байт")
    else:
        print(f"❌ Файл бази даних не існує: {db_path}")
    
    # Підключаємося до бази даних
    db = SQLiteClient(db_path)
    await db.connect()
    print("✅ Підключено до SQLite")
    
    # Тестуємо базові операції
    print("\n== Базові операції ==")
    test_key = "test_integration_key"
    test_value = "test_value_" + str(int(asyncio.get_event_loop().time()))
    
    # Записуємо дані
    await db.set(test_key, test_value)
    print(f"✅ Записано ключ: {test_key} = {test_value}")
    
    # Зчитуємо дані
    value = await db.get(test_key)
    if value == test_value:
        print(f"✅ Зчитано значення: {value}")
    else:
        print(f"❌ Отримано неправильне значення: {value}, очікувалося: {test_value}")
    
    # Інкремент
    await db.set("counter_test", "10")
    incremented = await db.incr("counter_test")
    if incremented == 11:
        print(f"✅ Інкремент працює: значення = {incremented}")
    else:
        print(f"❌ Інкремент не працює: значення = {incremented}, очікувалося: 11")
    
    # Видалення
    await db.delete(test_key)
    value_after_delete = await db.get(test_key)
    if value_after_delete is None:
        print(f"✅ Ключ успішно видалено")
    else:
        print(f"❌ Ключ не видалено: {value_after_delete}")
    
    # Перевіряємо таблиці
    print("\n== Перевірка таблиць ==")
    try:
        tables = await db.get_tables()
        print(f"✅ Знайдено таблиці: {', '.join(tables)}")
    except Exception as e:
        print(f"❌ Не вдалося отримати список таблиць: {e}")
        # Додаємо функцію для отримання таблиць
        tables = []
    
    # Перевіряємо записи в таблицях
    if "anomalies" in tables:
        try:
            anomalies = await db.get_recent_anomalies(3)
            print(f"✅ Знайдено {len(anomalies)} аномалій")
            
            for anomaly in anomalies:
                print(f"   Аномалія: {anomaly.get('source')} -> {anomaly.get('destination')}")
                print(f"   Рішення: {anomaly.get('decision')}, ризик: {anomaly.get('risk_score')}")
                print(f"   Теги: {', '.join(anomaly.get('tags', []))}")
                print(f"   Час: {anomaly.get('timestamp')}")
                print()
        except Exception as e:
            print(f"❌ Не вдалося отримати аномалії: {e}")
    
    # Тестуємо компоненти, що використовують SQLite
    print("\n== Тестування Rate Limiter ==")
    limiter = RateLimiter()
    await limiter.init()
    
    test_number = "+380987654321"
    count_before = await limiter.get_count(test_number)
    print(f"Поточний лічильник для {test_number}: {count_before}")
    
    # Інкрементуємо лічильник
    new_count = await limiter.increment(test_number)
    print(f"✅ Лічильник збільшено: {new_count}")
    
    # Перевіряємо, чи дозволено надсилання
    is_allowed = await limiter.is_allowed(test_number)
    print(f"✅ Надсилання дозволено: {is_allowed}")
    
    # Перевіряємо обмеження швидкості
    rate_result = await limiter.check_rate_limit("TestSender", test_number)
    print(f"✅ Перевірка обмеження швидкості: {rate_result}")
    
    print("\n== Тестування Blacklists Analyzer ==")
    blacklist = BlacklistsAnalyzer()
    await blacklist.init()
    
    # Додаємо тестовий елемент у чорний список
    test_item = "test_blacklist_item_" + str(int(asyncio.get_event_loop().time()))
    added = await blacklist.add_to_blacklist(test_item, "test")
    print(f"✅ Додано до чорного списку: {test_item}, результат: {added}")
    
    # Перевіряємо наявність у чорному списку
    check_result = await blacklist.check_sender(test_item)
    print(f"✅ Перевірка чорного списку: {check_result}")
    
    # Перевіряємо аналіз вмісту повідомлення
    message_result = await blacklist.check_message_content("Тестове повідомлення без шкідливого вмісту")
    print(f"✅ Перевірка вмісту повідомлення: {message_result}")
    
    print("\n=== Тестування завершено ===")
    await db.disconnect()

# Додаткова функція для отримання списку таблиць
async def get_tables(self):
    """Отримує список таблиць у базі даних SQLite"""
    with self.lock:
        try:
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            return [row['name'] for row in self.cursor.fetchall()]
        except Exception as e:
            raise Exception(f"Помилка отримання списку таблиць: {e}")

# Додаємо метод до класу SQLiteClient
SQLiteClient.get_tables = get_tables

if __name__ == "__main__":
    asyncio.run(test_sqlite())