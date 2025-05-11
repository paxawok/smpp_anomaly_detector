import re
import json
import asyncio
from typing import List, Tuple, Pattern, Dict, Any, Optional

from storage.sqlite_client import SQLiteClient
from logger.logger import SMPPLogger

logger = SMPPLogger("blacklists_analyzer")

class PhishingDetector:
    """
    Клас для виявлення фішингових повідомлень за допомогою регулярних виразів.
    """
    
    def __init__(self):
        # Список патернів у форматі: (скомпільований регулярний вираз, опис/пояснення)
        self.patterns: List[Tuple[Pattern, str]] = [
            # Виявляє повідомлення про блокування карток з посиланням
            # Приклад: "Ваша картка заблокована! Перейдіть за посиланням: bit.ly/12345"
            (re.compile(
                r'(?:карт(?:к|оч)(?:а|у|и|ою)|card).*?заблок(?:ова|ирова)н'
                r'.*?(?:перейд(?:іть|ите)|click|тисн(?:іть|ите)).*?(?:https?://|www\.|bit\.ly)',
                re.IGNORECASE), 
             "Повідомлення про блокування картки з посиланням"),
            
            # Виявляє повідомлення, що імітують банки з підозрілими URL
            # Приклад: "monobank: Підтвердіть транзакцію за посиланням mono-secure.com"
            (re.compile(
                r'(?:monobank|приватбанк|privat24|ощадбанк|банк|bank)'
                r'.*?(?:підтверд(?:іть|ите)|підтвердження|verify)'
                r'.*?(?:https?://|www\.|http)',
                re.IGNORECASE),
             "Імітація банку з підозрілим URL"),
            
            # Виявляє повідомлення про виграш призу/грошей
            # Приклад: "Вітаємо! Ви виграли 10000 грн! Для отримання перейдіть: example.com"
            (re.compile(
                r'(?:ви[\s-]+виграли|поздоровля(?:єм|ем)|вітаємо|congratulations)'
                r'.*?(?:\d+(?:\s*грн|\s*₴|\s*uah|\s*грив|\s*гривень|\s*usd|\s*\$)|\d+\s*000)'
                r'.*?(?:отрим|забрати|claim|click|перейд|тисн)',
                re.IGNORECASE),
             "Повідомлення про виграш призу чи грошей"),
            
            # Виявляє прохання ввести особисті дані або код
            # Приклад: "Для підтвердження введіть код з SMS: 1234 на сайті verify-code.com"
            (re.compile(
                r'(?:введ(?:іть|ите)|enter).*?(?:код|code|pin|пароль|password)'
                r'.*?(?:https?://|www\.|http)',
                re.IGNORECASE),
             "Прохання ввести особисті дані або код"),
            
            # Виявляє повідомлення з підозрілими скороченими URL
            # Приклад: "Перевірте статус вашого замовлення: bit.ly/2ab3F або t.co/ab12"
            (re.compile(
                r'(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd)/[a-zA-Z0-9]{4,}',
                re.IGNORECASE),
             "Підозрілі скорочені URL")
        ]
    
    def is_blacklisted(self, text: str) -> bool:
        """
        Перевіряє, чи текст відповідає хоча б одному з фішингових патернів.
        
        Args:
            text: Текст повідомлення для перевірки.
            
        Returns:
            bool: True, якщо текст відповідає хоча б одному патерну, False - якщо жодному.
        """
        if not text:
            return False
        
        for pattern, _ in self.patterns:
            if pattern.search(text):
                return True
        
        return False
    
    def check_with_details(self, text: str) -> List[str]:
        """
        Перевіряє текст на відповідність всім патернам і повертає список виявлених проблем.
        
        Args:
            text: Текст повідомлення для перевірки.
            
        Returns:
            List[str]: Список описів виявлених фішингових патернів.
        """
        if not text:
            return []
        
        found_issues = []
        
        for pattern, description in self.patterns:
            if pattern.search(text):
                found_issues.append(description)
        
        return found_issues


class BlacklistsAnalyzer:
    """
    Клас для аналізу чорних списків відправників та шаблонів повідомлень
    з використанням Redis для збереження чорних списків
    """
    def __init__(self):
        self.phishing_detector = PhishingDetector()
        self.redis_client = SQLiteClient()
        self.initialized = False
    
    async def init(self) -> None:
        """Ініціалізація підключення до Redis"""
        await self.redis_client.connect()
        self.initialized = True
    
    async def check_sender(self, sender: str) -> Dict[str, Any]:
        """
        Перевіряє відправника на присутність у чорному списку
        
        Args:
            sender: Ідентифікатор відправника
                
        Returns:
            dict: Результат перевірки у форматі 
                  {"is_blacklisted": bool, "risk_score": float, "category": str}
        """
        if not self.initialized:
            await self.init()
        
        # Перевіряємо відправника в Redis чорному списку
        try:
            result = await self.redis_client.check_blacklist(sender, "sender")
            
            if result["is_blacklisted"]:
                logger.info(f"Знайдено відправника '{sender}' у чорному списку: {result['category']}")
                return {
                    "is_blacklisted": True,
                    "risk_score": 1.0,
                    "category": result["category"]
                }
                
            # Якщо не знайдено, повертаємо негативний результат
            return {
                "is_blacklisted": False,
                "risk_score": 0.0,
                "category": ""
            }
        except Exception as e:
            logger.error(f"Помилка перевірки відправника в чорному списку: {e}")
            # У випадку помилки вважаємо, що відправник не в чорному списку
            return {
                "is_blacklisted": False,
                "risk_score": 0.0,
                "category": ""
            }
    
    async def add_to_blacklist(self, item: str, category: str = "sender", 
                             reason: str = "", ttl: Optional[int] = None) -> bool:
        """
        Додає відправника або шаблон до чорного списку
        
        Args:
            item: Елемент для додавання (sender id, шаблон, тощо)
            category: Категорія (sender, domain, pattern)
            reason: Причина додавання
            ttl: Час життя запису в секундах (None - безстроково)
            
        Returns:
            bool: Результат операції
        """
        if not self.initialized:
            await self.init()
            
        try:
            return await self.redis_client.add_to_blacklist(item, category, reason, ttl)
        except Exception as e:
            logger.error(f"Помилка додавання до чорного списку: {e}")
            return False
    
    async def check_message_content(self, message: str) -> Dict[str, Any]:
        """
        Перевіряє вміст повідомлення на наявність шаблонів фішингу та
        на входження в чорний список шаблонів
        
        Args:
            message: Текст повідомлення
                
        Returns:
            dict: Результат перевірки у форматі 
                  {"is_suspicious": bool, "risk_score": float, "categories": list}
        """
        if not self.initialized:
            await self.init()
            
        # Використовуємо PhishingDetector для перевірки шаблонів
        is_suspicious_pattern = self.phishing_detector.is_blacklisted(message)
        pattern_details = []
        
        if is_suspicious_pattern:
            pattern_details = self.phishing_detector.check_with_details(message)
        
        # Перевіряємо, чи є точне співпадіння з чорним списком шаблонів
        try:
            content_blacklist_result = await self.redis_client.check_blacklist(message, "pattern")
            
            if content_blacklist_result["is_blacklisted"]:
                # Якщо знайдено в чорному списку, додаємо до результатів
                is_suspicious_pattern = True
                if content_blacklist_result["category"] and content_blacklist_result["category"] not in pattern_details:
                    pattern_details.append(content_blacklist_result["category"])
        except Exception as e:
            logger.error(f"Помилка перевірки шаблону в чорному списку: {e}")
        
        # Підготовка результату
        risk_score = 0.8 if is_suspicious_pattern else 0.0
        
        # Якщо знайдено в чорному списку з високим ризиком, підвищуємо оцінку
        if content_blacklist_result and content_blacklist_result.get("is_blacklisted"):
            risk_score = max(risk_score, content_blacklist_result.get("risk_score", 0.8))
            
        return {
            "is_suspicious": is_suspicious_pattern,
            "risk_score": risk_score,
            "categories": pattern_details
        }

# Створюємо глобальний екземпляр для використання в різних модулях
phishing_detector = PhishingDetector()
blacklists_analyzer = BlacklistsAnalyzer()

# Функція для ініціалізації глобального екземпляра
async def init_blacklists_analyzer() -> None:
    await blacklists_analyzer.init()

def is_blacklisted(text: str) -> bool:
    """
    Глобальна функція для перевірки, чи текст відповідає хоча б одному з фішингових патернів.
    
    Args:
        text: Текст повідомлення для перевірки.
        
    Returns:
        bool: True, якщо текст відповідає хоча б одному патерну, False - якщо жодному.
    """
    return phishing_detector.is_blacklisted(text)

# Приклад використання
if __name__ == "__main__":
    # Тестові повідомлення
    test_messages = [
        "Привіт! Як справи?",
        "Ваша картка ПриватБанку заблокована! Для розблокування перейдіть за посиланням: bit.ly/12345abc",
        "monobank: Підтвердіть транзакцію на суму 1299 грн за посиланням mono-secure.com",
        "Вітаємо! Ви виграли 10000 грн! Для отримання призу перейдіть: lottery-win.com/claim",
        "Для підтвердження входу введіть код з SMS: 1234 на сайті verify-account.com",
        "Перевірте статус вашого замовлення: bit.ly/2ab3F",
        "Дякуємо за покупку! Ваше замовлення #12345 прийнято в обробку."
    ]
    
    async def test_blacklists():
        # Ініціалізуємо аналізатор чорних списків
        await blacklists_analyzer.init()
        
        # Додаємо один приклад до чорного списку
        await blacklists_analyzer.add_to_blacklist(
            "verify-account.com", 
            category="domain", 
            reason="Phishing domain used in tests"
        )
        
        print("=== Перевірка повідомлень на фішинг ===")
        for i, message in enumerate(test_messages):
            result = await blacklists_analyzer.check_message_content(message)
            status = "ФІШИНГ" if result["is_suspicious"] else "Безпечне"
            score = result["risk_score"]
            
            print(f"Повідомлення #{i+1}: {status} (ризик: {score:.2f})")
            print(f"Текст: {message}")
            
            # Виводимо категорії, якщо є
            if result["categories"]:
                print(f"Виявлено: {', '.join(result['categories'])}")
            
            print("-" * 60)
        
        print("\n=== Перевірка відправників ===")
        test_senders = ["СпамБанк", "InfoService", "MyBank"]
        
        # Додаємо один приклад до чорного списку
        await blacklists_analyzer.add_to_blacklist(
            "СпамБанк", 
            category="sender", 
            reason="Known spam sender"
        )
        
        for sender in test_senders:
            result = await blacklists_analyzer.check_sender(sender)
            status = "ЗАБЛОКОВАНО" if result["is_blacklisted"] else "Дозволено"
            print(f"Відправник '{sender}': {status}")
            if result["is_blacklisted"]:
                print(f"  Категорія: {result['category']}")
                print(f"  Оцінка ризику: {result['risk_score']:.2f}")
            print("-" * 40)
    
    # Запускаємо тест
    asyncio.run(test_blacklists())