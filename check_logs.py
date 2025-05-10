import os
import json
from datetime import datetime

def check_logs(log_file="logs/smpp_log.jsonl"):
    """
    Перевіряє файл логів і виводить інформацію про аномалії
    """
    print("=" * 80)
    print("ПЕРЕВІРКА ЛОГІВ SMPP")
    print("=" * 80)
    
    # Перевіряємо наявність директорії та файлу
    logs_dir = os.path.dirname(log_file)
    if not os.path.exists(logs_dir):
        print(f"Директорія логів '{logs_dir}' не існує")
        print(f"Створюємо директорію '{logs_dir}'...")
        os.makedirs(logs_dir, exist_ok=True)
        print(f"Директорія '{logs_dir}' створена")
    
    if not os.path.exists(log_file):
        print(f"Файл логів '{log_file}' не існує")
        print("Ймовірно, система не створює файл логів або має проблеми з правами доступу")
    else:
        print(f"Файл логів '{log_file}' знайдено")
        
        # Читаємо логи
        entries = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except:
                    pass
        
        # Виводимо інформацію про логи
        print(f"Знайдено {len(entries)} записів у файлі логів")
        
        # Шукаємо записи аномалій
        anomalies = [entry for entry in entries if entry.get("level") == "ANOMALY"]
        print(f"Знайдено {len(anomalies)} записів аномалій")
        
        if anomalies:
            print("\nЗнайдені аномалії:")
            for i, anomaly in enumerate(anomalies, 1):
                timestamp = anomaly.get("timestamp", "")
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        timestamp = dt.strftime("%H:%M:%S")
                    except:
                        pass
                
                message = anomaly.get("message", "")
                source = anomaly.get("source", "")
                dest = anomaly.get("dest", "")
                decision = anomaly.get("decision", "")
                risk_score = anomaly.get("risk_score", 0)
                tags = ", ".join(anomaly.get("tags", []))
                
                print(f"  {i}. [{timestamp}] {source} -> {dest}")
                print(f"     Рішення: {decision.upper()}, Ризик: {risk_score}")
                print(f"     Теги: {tags}")
                print(f"     Повідомлення: {message}")
                print()
        else:
            print("\nАномалій не знайдено. Можливі причини:")
            print("  1. Системі не вдається записувати аномалії у файл")
            print("  2. Відсутні права доступу до файлу логів")
            print("  3. Функція logger.anomaly() не викликається або працює некоректно")
    
    print("\nРекомендації для виправлення:")
    print("  1. Перевірте, чи коректно викликається logger.anomaly() в обробнику")
    print("  2. Переконайтеся, що директорія логів має правильні права доступу")
    print("  3. Спробуйте додати безпосередній виклик запису в файл логів")
    print("=" * 80)

if __name__ == "__main__":
    check_logs()