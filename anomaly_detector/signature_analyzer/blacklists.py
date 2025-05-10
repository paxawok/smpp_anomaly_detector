import re
from typing import List, Tuple, Pattern


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


# Створюємо глобальний екземпляр для використання в різних модулях
phishing_detector = PhishingDetector()


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
    
    # Перевіряємо кожне повідомлення
    for i, message in enumerate(test_messages):
        is_phishing = is_blacklisted(message)
        status = "ФІШИНГ" if is_phishing else "Безпечне"
        print(f"Повідомлення #{i+1}: {status}")
        print(f"Текст: {message}")
        
        # Якщо це фішинг, виводимо деталі
        if is_phishing:
            details = phishing_detector.check_with_details(message)
            print(f"Виявлено: {', '.join(details)}")
        
        print("-" * 60)