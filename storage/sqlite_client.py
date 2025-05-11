# storage/sqlite_client.py
import os
import json
import sqlite3
import time
from typing import Optional, Dict, List, Any
import threading

try:
    from logger.logger import SMPPLogger
    logger = SMPPLogger("sqlite_client")
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("sqlite_client")

class SQLiteClient:
    """
    Спрощений клієнт для роботи з SQLite
    """
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("SQLITE_DB_PATH", "storage/anomaly_detector.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.connection = None
        self.cursor = None
        self.lock = threading.RLock()
        
        logger.info(f"SQLite клієнт ініціалізовано, БД: {self.db_path}")
    
    async def connect(self) -> None:
        """Підключення до бази даних"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
            
            # Створюємо таблиці
            self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS key_value (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at INTEGER NULL
            )
            """)
            
            self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                source TEXT,
                destination TEXT,
                message TEXT,
                risk_score REAL,
                decision TEXT,
                tags TEXT
            )
            """)
            
            self.connection.commit()
            logger.info(f"Підключено до бази даних SQLite: {self.db_path}")
            
        except Exception as e:
            logger.error(f"Помилка підключення до SQLite: {e}")
            # Fallback - підключення в пам'яті
            self.connection = sqlite3.connect(":memory:", check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
            # Створюємо ті ж таблиці
            self.cursor.execute("CREATE TABLE IF NOT EXISTS key_value (key TEXT PRIMARY KEY, value TEXT, expires_at INTEGER NULL)")
            self.cursor.execute("CREATE TABLE IF NOT EXISTS anomalies (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, source TEXT, destination TEXT, message TEXT, risk_score REAL, decision TEXT, tags TEXT)")
            self.connection.commit()
            logger.info("Створено підключення в пам'яті")
    
    async def disconnect(self) -> None:
        """Відключення від бази даних"""
        if self.connection:
            self.connection.close()
            logger.info("Відключено від бази даних SQLite")
    
    async def get(self, key: str) -> Any:
        """Отримання значення за ключем"""
        if not self.connection:
            await self.connect()
            
        with self.lock:
            try:
                self.cursor.execute(
                    "SELECT value, expires_at FROM key_value WHERE key = ?",
                    (key,)
                )
                row = self.cursor.fetchone()
                
                if row:
                    # Перевіряємо термін дії
                    expires_at = row['expires_at']
                    if expires_at is not None and expires_at <= time.time():
                        self.cursor.execute("DELETE FROM key_value WHERE key = ?", (key,))
                        self.connection.commit()
                        return None
                    
                    return row['value']
                
                return None
            
            except Exception as e:
                logger.error(f"Помилка при отриманні ключа {key}: {e}")
                return None
    
    async def set(self, key: str, value: str, expire: Optional[int] = None) -> bool:
        """Встановлення значення за ключем"""
        if not self.connection:
            await self.connect()
            
        expires_at = time.time() + expire if expire else None
        
        with self.lock:
            try:
                self.cursor.execute(
                    "INSERT OR REPLACE INTO key_value (key, value, expires_at) VALUES (?, ?, ?)",
                    (key, value, expires_at)
                )
                self.connection.commit()
                return True
            
            except Exception as e:
                logger.error(f"Помилка при встановленні ключа {key}: {e}")
                return False
    
    async def delete(self, key: str) -> int:
        """Видалення значення за ключем"""
        if not self.connection:
            await self.connect()
            
        with self.lock:
            try:
                self.cursor.execute("DELETE FROM key_value WHERE key = ?", (key,))
                rows_affected = self.cursor.rowcount
                self.connection.commit()
                return rows_affected
            
            except Exception as e:
                logger.error(f"Помилка при видаленні ключа {key}: {e}")
                return 0
    
    async def incr(self, key: str) -> int:
        """Інкремент значення за ключем"""
        if not self.connection:
            await self.connect()
            
        with self.lock:
            # Отримуємо поточне значення
            current_value = await self.get(key)
            
            try:
                if current_value is None:
                    new_value = 1
                else:
                    try:
                        new_value = int(current_value) + 1
                    except (ValueError, TypeError):
                        new_value = 1
                
                # Зберігаємо нове значення
                await self.set(key, str(new_value))
                return new_value
            
            except Exception as e:
                logger.error(f"Помилка при інкременті ключа {key}: {e}")
                return 1
    
    async def check_rate_limit(self, source_addr: str, destination_addr: str, 
                            daily_limit: int = 30) -> Dict[str, Any]:
        """Перевіряє обмеження швидкості"""
        key = f"rate_limit:{source_addr}:{destination_addr}"
        count = await self.incr(key)
        
        # Оцінка ризику
        risk_score = min(1.0, count / daily_limit * 0.8)
        
        return {
            "exceeded": count > daily_limit,
            "count": count,
            "limit": daily_limit,
            "risk_score": risk_score
        }
    
    async def add_to_blacklist(self, item: str, category: str = "general") -> bool:
        """Додавання елемента до чорного списку"""
        key = f"blacklist:{category}:{item}"
        data = json.dumps({
            "item": item,
            "category": category,
            "added_at": time.time()
        })
        
        return await self.set(key, data)
    
    async def check_blacklist(self, item: str, category: Optional[str] = None) -> Dict[str, Any]:
        """Перевірка елемента на наявність у чорному списку"""
        if category:
            key = f"blacklist:{category}:{item}"
            data = await self.get(key)
            if data:
                return {
                    "is_blacklisted": True,
                    "category": category,
                    "data": json.loads(data),
                    "risk_score": 1.0
                }
        else:
            for cat in ["general", "spam", "phishing", "fraud"]:
                result = await self.check_blacklist(item, cat)
                if result.get("is_blacklisted"):
                    return result
                
        return {
            "is_blacklisted": False,
            "category": "",
            "data": None,
            "risk_score": 0.0
        }
    
    async def record_anomaly(self, data: Dict[str, Any]) -> bool:
        """Записує виявлену аномалію"""
        if not self.connection:
            await self.connect()
            
        try:
            timestamp = data.get("timestamp", time.time())
            source = data.get("source", "unknown")
            destination = data.get("dest", "unknown")
            message = data.get("message", "")
            risk_score = data.get("risk_score", 0.0)
            decision = data.get("decision", "unknown")
            tags = json.dumps(data.get("tags", []))
            
            with self.lock:
                self.cursor.execute(
                    """
                    INSERT INTO anomalies 
                    (timestamp, source, destination, message, risk_score, decision, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, source, destination, message, risk_score, decision, tags)
                )
                
                self.connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Помилка запису аномалії: {e}")
            return False
    
    async def get_recent_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Отримання останніх аномалій"""
        if not self.connection:
            await self.connect()
            
        with self.lock:
            try:
                self.cursor.execute(
                    """
                    SELECT * FROM anomalies 
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,)
                )
                
                result = []
                for row in self.cursor.fetchall():
                    anomaly = dict(row)
                    anomaly['tags'] = json.loads(anomaly['tags'])
                    result.append(anomaly)
                
                return result
                
            except Exception as e:
                logger.error(f"Помилка при отриманні останніх аномалій: {e}")
                return []
    
    async def get_stats(self) -> Dict[str, Any]:
        """Отримання статистики"""
        if not self.connection:
            await self.connect()
            
        with self.lock:
            try:
                stats = {
                    "status": "connected" if self.connection else "disconnected",
                    "db_path": self.db_path,
                    "anomalies": {}
                }
                
                # Статистика аномалій
                self.cursor.execute("SELECT COUNT(*) AS count FROM anomalies")
                row = self.cursor.fetchone()
                stats["anomalies"]["total"] = row["count"] if row else 0
                
                self.cursor.execute("SELECT decision, COUNT(*) AS count FROM anomalies GROUP BY decision")
                for row in self.cursor.fetchall():
                    stats["anomalies"][row["decision"]] = row["count"]
                
                return stats
                
            except Exception as e:
                logger.error(f"Помилка при отриманні статистики: {e}")
                return {"status": "error", "error": str(e)}