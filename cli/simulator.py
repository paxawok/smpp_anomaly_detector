#!/usr/bin/env python
import asyncio
import random
import time
import argparse
import string
import sys
import os
import json
from typing import List, Dict, Any, Optional, Tuple

# Додаємо батьківський каталог до шляху для імпорту
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logger.logger import SMPPLogger
from smpp_proxy.client import SMPPClient

logger = SMPPLogger("simulator")

class SMPPTrafficSimulator:
    """
    Клас для симуляції різних типів SMPP трафіку
    """
    def __init__(
        self,
        host: str = "localhost",
        port: int = 2775,
        system_id: str = "simulator",
        password: str = "password",
        use_tls: bool = False
    ):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.use_tls = use_tls
        
        # Клієнт SMPP
        self.client = None
        
        # Типи повідомлень
        self.message_types = {
            "normal": self._generate_normal_messages,
            "suspicious": self._generate_suspicious_messages,
            "phishing": self._generate_phishing_messages,
            "flood": self._generate_flood_messages,
            "mixed": self._generate_mixed_messages
        }
        
        # Відправники
        self.normal_senders = [
            "InfoBank", "Service", "Store", "Rozetka", "Nova", "OLX",
            "Uber", "Glovo", "UkrPost", "NovaPoshta", "Apple", "Google"
        ]
        
        self.suspicious_senders = [
            "INFO", "Admin", "System", "Alert", "Bank", "Service",
            "A1234", "Support", "0", "News", "SPAM", "XXX", "100"
        ]
        
        # Префікси телефонів
        self.normal_prefixes = ["067", "068", "096", "097", "098", "050", "066", "095", "099", "063", "073", "093"]
        self.suspicious_prefixes = ["7978", "7989", "38071", "38072", "7", "375"]
        
        logger.info(
            f"Симулятор ініціалізовано для {host}:{port}, "
            f"system_id: {system_id}, use_tls: {use_tls}"
        )
    
    async def connect(self) -> bool:
        """
        З'єднується з SMPP сервером
        """
        self.client = SMPPClient(
            host=self.host,
            port=self.port,
            system_id=self.system_id,
            password=self.password,
            use_tls=self.use_tls
        )
        
        connected = await self.client.connect()
        if connected:
            result = await self.client.bind_transmitter()
            if result.get("command_status") == 0:
                logger.info(f"З'єднано з SMPP сервером {self.host}:{self.port}")
                return True
            else:
                logger.error(f"Помилка при bind: {result}")
                return False
        else:
            logger.error(f"Не вдалося з'єднатися з SMPP сервером {self.host}:{self.port}")
            return False
    
    async def disconnect(self) -> None:
        """
        Відключається від SMPP сервера
        """
        if self.client:
            await self.client.disconnect()
            logger.info(f"Відключено від SMPP сервера {self.host}:{self.port}")
    
    async def run_simulation(
        self, 
        traffic_type: str, 
        message_count: int, 
        interval: float,
        verbose: bool = False
    ) -> None:
        """
        Запускає симуляцію трафіку
        """
        if not self.client:
            logger.error("Клієнт не ініціалізовано, спочатку викличте connect()")
            return
        
        if traffic_type not in self.message_types:
            logger.error(f"Невідомий тип трафіку: {traffic_type}")
            logger.info(f"Доступні типи: {', '.join(self.message_types.keys())}")
            return
        
        logger.info(f"Запуск симуляції трафіку типу '{traffic_type}', {message_count} повідомлень")
        
        # Отримуємо генератор повідомлень для вибраного типу
        message_generator = self.message_types[traffic_type]
        
        # Генеруємо і відправляємо повідомлення
        for i in range(message_count):
            message_data = message_generator()
            
            if verbose:
                logger.info(
                    f"Відправлення {i+1}/{message_count}: "
                    f"{message_data['source_addr']} -> {message_data['destination_addr']}: "
                    f"{message_data['short_message'][:30]}..."
                )
            
            try:
                result = await self.client.submit_sm(
                    source_addr=message_data["source_addr"],
                    destination_addr=message_data["destination_addr"],
                    short_message=message_data["short_message"],
                    source_addr_ton=message_data.get("source_addr_ton", 5),
                    source_addr_npi=message_data.get("source_addr_npi", 0),
                    dest_addr_ton=message_data.get("dest_addr_ton", 1),
                    dest_addr_npi=message_data.get("dest_addr_npi", 1)
                )
                
                if result.get("command_status") != 0:
                    logger.warning(f"Помилка відправлення: {result}")
            except Exception as e:
                logger.error(f"Помилка: {e}")
            
            # Пауза між повідомленнями
            await asyncio.sleep(interval)
        
        logger.info(f"Симуляцію завершено. Відправлено {message_count} повідомлень")
    
    def _generate_normal_messages(self) -> Dict[str, Any]:
        """
        Генерує звичайне повідомлення
        """
        sender = random.choice(self.normal_senders)
        destination = "38" + random.choice(self.normal_prefixes) + ''.join(random.choices(string.digits, k=7))
        
        templates = [
            "Ваш код підтвердження: {code}. Нікому його не повідомляйте.",
            "Дякуємо за замовлення #{order_id}. Статус можна перевірити на сайті.",
            "Ваше замовлення #{order_id} відправлено. Очікуйте доставку {date}.",
            "Вітаємо! Ви отримали бонус {bonus} грн на наступну покупку.",
            "Нагадуємо про оплату рахунку до {date}. Сума: {amount} грн.",
            "Баланс Вашого рахунку: {amount} грн.",
            "Запрошуємо на розпродаж! Знижки до 50% з {date} по {end_date}.",
            "Дякуємо, що користуєтесь нашими послугами!",
            "Оплата успішна. Сума: {amount} грн. Залишок: {balance} грн."
        ]
        
        template = random.choice(templates)
        message = template.format(
            code=random.randint(1000, 9999),
            order_id=random.randint(100000, 999999),
            date=f"{random.randint(1, 30)}.{random.randint(1, 12)}.2025",
            end_date=f"{random.randint(1, 30)}.{random.randint(1, 12)}.2025",
            amount=random.randint(50, 5000),
            balance=random.randint(100, 10000),
            bonus=random.randint(10, 500)
        )
        
        return {
            "source_addr": sender,
            "destination_addr": destination,
            "short_message": message
        }
    
    def _generate_suspicious_messages(self) -> Dict[str, Any]:
        """
        Генерує підозрілі повідомлення
        """
        sender = random.choice(self.suspicious_senders)
        
        # 75% нормальних номерів, 25% підозрілих
        if random.random() < 0.75:
            destination = "38" + random.choice(self.normal_prefixes) + ''.join(random.choices(string.digits, k=7))
        else:
            destination = random.choice(self.suspicious_prefixes) + ''.join(random.choices(string.digits, k=8))
        
        templates = [
            "Ви виграли приз! Забрати за посиланням: {url}",
            "Ваша картка заблокована! Перевірте: {url}",
            "УВАГА! Ваш аккаунт під загрозою. Деталі: {url}",
            "Підтвердіть оплату через: {url}",
            "Вам нараховано кешбек. Отримати: {url}",
            "Знижка 90% тільки сьогодні! {url}",
            "Перейдіть за посиланням для підтвердження: {url}",
            "Ваше фото опубліковано тут: {url}",
            "ВАЖЛИВО: перевірте свій статус: {url}"
        ]
        
        # Генеруємо підозрілі URL
        suspicious_domains = [
            "bit.ly/a1b2c3", "tiny.url/qwerty", "clck.ru/abcdef",
            "secure-login.com/verify", "bank-check.net/account",
            "get-prize-now.site/win", "account-verify.co/check",
            "monobänk.com/login", "рrivat24.com/access"
        ]
        
        template = random.choice(templates)
        message = template.format(url=random.choice(suspicious_domains))
        
        return {
            "source_addr": sender,
            "destination_addr": destination,
            "short_message": message
        }
    
    def _generate_phishing_messages(self) -> Dict[str, Any]:
        """
        Генерує фішингові повідомлення, які імітують банки
        """
        # Імітуємо відомі банки з невеликими змінами
        bank_senders = [
            "Monobank", "M0nobank", "MonoВank", "Mono bank",
            "Pr1vatBank", "Privа4Bank", "PrуvatBank",
            "PRIVAT24", "PR1VAT24", "OschadЬank", "OshаdBank"
        ]
        
        sender = random.choice(bank_senders)
        destination = "38" + random.choice(self.normal_prefixes) + ''.join(random.choices(string.digits, k=7))
        
        templates = [
            "Ваша картка {card} заблокована! Для розблокування перейдіть: {url}",
            "Виявлено підозрілу транзакцію на {amount} грн. Підтвердіть: {url}",
            "Термінове повідомлення від банку! Ваш рахунок буде заблоковано. Деталі: {url}",
            "Для підтвердження переказу {amount} грн перейдіть: {url}",
            "Ваша заявка на кредит схвалена! Отримайте гроші: {url}",
            "Протерміновано оплату кредиту. Погасіть негайно: {url}",
            "УВАГА! Змінено дані входу до Вашого аккаунту. Перевірте: {url}",
            "Ваш бонус {bonus} грн доступний за посиланням: {url}",
            "Новий вхід до Вашого аккаунту. Якщо це не Ви, перейдіть: {url}"
        ]
        
        phishing_domains = [
            "mono-bank.online/secure", "my-monobank.site/id",
            "privat-24.info/login", "security-bank.xyz/check",
            "privatbankon.line/verify", "monobаnk.com/verify",
            "bank-verification.site/check", "verify-mono.app/sms",
            "safe-banking.online/login", "oschad-online.xyz/verify"
        ]
        
        template = random.choice(templates)
        message = template.format(
            card="*" + ''.join(random.choices(string.digits, k=4)),
            amount=random.randint(1000, 15000),
            bonus=random.randint(100, 1000),
            url=random.choice(phishing_domains)
        )
        
        return {
            "source_addr": sender,
            "destination_addr": destination,
            "short_message": message
        }
    
    def _generate_flood_messages(self) -> Dict[str, Any]:
        """
        Генерує повідомлення для імітації flood-атаки
        """
        # Використовуємо один відправник для всіх повідомлень флуду
        sender = random.choice([
            "INFO", "Service", "Admin", "System", 
            ''.join(random.choices(string.ascii_uppercase, k=random.randint(3, 6)))
        ])
        
        # Для flood використовуємо один і той же номер або невелику групу номерів
        if not hasattr(self, '_flood_destinations'):
            self._flood_destinations = [
                "38" + random.choice(self.normal_prefixes) + ''.join(random.choices(string.digits, k=7))
                for _ in range(3)
            ]
        
        destination = random.choice(self._flood_destinations)
        
        # Генеруємо просте повідомлення, часто однакове або з невеликими змінами
        templates = [
            "Перевірка системи #{id}",
            "Тест зв'язку #{id}",
            "Системне повідомлення #{id}",
            "Код: {code}",
            "Повідомлення #{id}"
        ]
        
        template = random.choice(templates)
        message = template.format(
            id=random.randint(1000, 9999),
            code=''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        )
        
        return {
            "source_addr": sender,
            "destination_addr": destination,
            "short_message": message
        }
    
    def _generate_mixed_messages(self) -> Dict[str, Any]:
        """
        Генерує мікс різних типів повідомлень з перевагою нормальних
        """
        # Вагові коефіцієнти для різних типів
        weights = {
            "normal": 0.7,      # 70% нормальних
            "suspicious": 0.1,  # 10% підозрілих
            "phishing": 0.1,    # 10% фішингових
            "flood": 0.1        # 10% flood
        }
        
        # Вибираємо тип на основі вагових коефіцієнтів
        r = random.random()
        cumulative = 0
        selected_type = "normal"  # За замовчуванням
        
        for msg_type, weight in weights.items():
            cumulative += weight
            if r <= cumulative:
                selected_type = msg_type
                break
        
        # Генеруємо повідомлення відповідного типу
        if selected_type == "normal":
            return self._generate_normal_messages()
        elif selected_type == "suspicious":
            return self._generate_suspicious_messages()
        elif selected_type == "phishing":
            return self._generate_phishing_messages()
        elif selected_type == "flood":
            return self._generate_flood_messages()
        else:
            return self._generate_normal_messages()


async def main():
    """
    Основна функція для запуску симулятора з командного рядка
    """
    parser = argparse.ArgumentParser(description="Симулятор SMPP трафіку для тестування системи виявлення аномалій")
    
    parser.add_argument("--host", default="localhost", help="Хост SMPP сервера")
    parser.add_argument("--port", type=int, default=2775, help="Порт SMPP сервера")
    parser.add_argument("--system-id", default="simulator", help="System ID для з'єднання")
    parser.add_argument("--password", default="password", help="Пароль для з'єднання")
    parser.add_argument("--tls", action="store_true", help="Використовувати TLS")
    
    parser.add_argument("--type", choices=["normal", "suspicious", "phishing", "flood", "mixed"],
                        default="mixed", help="Тип трафіку для симуляції")
    parser.add_argument("--count", type=int, default=10, help="Кількість повідомлень для відправки")
    parser.add_argument("--interval", type=float, default=1.0, 
                        help="Інтервал між повідомленнями в секундах")
    parser.add_argument("--verbose", "-v", action="store_true", help="Детальний вивід")
    
    args = parser.parse_args()
    
    # Створюємо і запускаємо симулятор
    simulator = SMPPTrafficSimulator(
        host=args.host,
        port=args.port,
        system_id=args.system_id,
        password=args.password,
        use_tls=args.tls
    )
    
    try:
        # З'єднуємося з сервером
        if await simulator.connect():
            # Запускаємо симуляцію
            await simulator.run_simulation(
                traffic_type=args.type,
                message_count=args.count,
                interval=args.interval,
                verbose=args.verbose
            )
        
    except KeyboardInterrupt:
        print("\nСимуляцію перервано користувачем")
    except Exception as e:
        print(f"Помилка: {e}")
    finally:
        # Закриваємо з'єднання
        await simulator.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
