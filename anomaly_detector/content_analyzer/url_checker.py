import os
import re
import json
import urllib.parse
from typing import Dict, List, Tuple, Any, Optional, Set

from logging.logger import SMPPLogger

logger = SMPPLogger("url_checker")

class URLChecker:
    """
    Клас для перевірки URL на підозрілість
    """
    def __init__(self, malicious_domains_file: Optional[str] = None):
        self.malicious_domains_file = malicious_domains_file or os.path.join(
            os.path.dirname(__file__), "data", "malicious_domains.json"
        )
        
        # Завантажуємо базу підозрілих доменів
        self.malicious_domains = self._load_malicious_domains()
        
        # Патерни для URL
        self.url_pattern = re.compile(
            r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|bit\.ly/[^\s<>"\']+|t\.me/[^\s<>"\']+'
        )
        
        # Патерни для сумнівних доменів
        self.short_url_domains = set([
            "bit.ly", "tinyurl.com", "cutt.ly", "goo.gl", "ow.ly",
            "t.co", "is.gd", "buff.ly", "tiny.cc", "qps.ru",
            "clck.ru", "v.gd", "goo.su", "b.link", "j.mp"
        ])
        
        # Ознаки підозрілих URL
        self.suspicious_url_indicators = [
            r'login', r'signin', r'account', r'verify', r'password',
            r'bank', r'secure', r'update', r'auth', r'confirm',
            r'\d{5,}',  # Багато цифр у домені
            r'[a-z]{15,}',  # Довгі послідовності літер
            r'\.(ru|cn|tk|ga|ml|cf|gq)\b',  # Підозрілі доменні зони
            r'[a-zA-Z0-9]{32,}\.', # Довгі рандомні доменні імена
            r'([a-z0-9])\1{3,}',   # Повторення символів
            r'google.*\.(?!com|com\.[a-z]{2})',  # Фальшивий Google
            r'facebook.*\.(?!com|net)',  # Фальшивий Facebook
            r'ukr\.net.*\.(?!ua)',  # Фальшивий UkrNet
            r'privat24.*\.(?!ua)',  # Фальшивий Privat24
            r'monobank.*\.(?!ua)',  # Фальшивий Monobank
        ]
        
        logger.info(f"URLChecker ініціалізовано з {len(self.malicious_domains)} відомими шкідливими доменами")
    
    def _load_malicious_domains(self) -> Dict[str, Dict[str, Any]]:
        """
        Завантажує базу підозрілих доменів з JSON файлу
        """
        try:
            # Створюємо директорію, якщо вона не існує
            os.makedirs(os.path.dirname(self.malicious_domains_file), exist_ok=True)
            
            # Якщо файл не існує, створюємо його з базовими доменами
            if not os.path.exists(self.malicious_domains_file):
                default_domains = {
                    "phishing": [
                        "secure-bank-login.com", 
                        "verify-card-info.net", 
                        "account-security-check.com",
                        "login-verification-service.com",
                        "monobank-verify.net",
                        "privatbank-login.com",
                        "privat24-secure.net",
                        "bank-verify-id.com"
                    ],
                    "malware": [
                        "download-free-antivirus.net", 
                        "system-cleaner-pro.com",
                        "fast-browser-update.com",
                        "security-protect-update.net"
                    ],
                    "spam": [
                        "free-prizes-now.com", 
                        "win-lottery-online.net",
                        "best-casino-bonus.com",
                        "dating-hot-girls.com"
                    ]
                }
                
                with open(self.malicious_domains_file, "w", encoding="utf-8") as f:
                    json.dump(default_domains, f, ensure_ascii=False, indent=2)
                
                # Створюємо єдиний словник для зручного пошуку
                result = {}
                for category, domains in default_domains.items():
                    for domain in domains:
                        result[domain] = {"category": category, "score": 1.0}
                
                return result
            
            # Інакше завантажуємо існуючий файл
            with open(self.malicious_domains_file, "r", encoding="utf-8") as f:
                domains_by_category = json.load(f)
                
                # Перетворюємо в єдиний словник для зручного пошуку
                result = {}
                for category, domains in domains_by_category.items():
                    for domain in domains:
                        result[domain] = {"category": category, "score": 1.0}
                
                return result
                
        except Exception as e:
            logger.error(f"Помилка завантаження бази підозрілих доменів: {e}")
            # Повертаємо пустий словник у випадку помилки
            return {}
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Витягує URL з тексту
        """
        if not text:
            return []
            
        return self.url_pattern.findall(text)
    
    def extract_domain(self, url: str) -> Optional[str]:
        """
        Витягує домен з URL
        """
        try:
            # Додаємо схему, якщо відсутня
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            # Парсимо URL
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # Видаляємо порт, якщо присутній
            if ':' in domain:
                domain = domain.split(':')[0]
                
            # Перевіряємо, що домен не порожній
            if not domain:
                return None
                
            return domain.lower()
            
        except Exception as e:
            logger.error(f"Помилка витягування домену з URL '{url}': {e}")
            return None
    
    def is_short_url(self, url: str) -> bool:
        """
        Перевіряє, чи є URL скороченим
        """
        domain = self.extract_domain(url)
        if not domain:
            return False
            
        return domain in self.short_url_domains
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Перевіряє URL на підозрілість
        """
        result = {
            "url": url,
            "domain": None,
            "is_malicious": False,
            "is_suspicious": False,
            "is_short_url": False,
            "category": None,
            "risk_score": 0.0,
            "indicators": []
        }
        
        # Витягуємо домен
        domain = self.extract_domain(url)
        if not domain:
            return result
            
        result["domain"] = domain
        
        # Перевіряємо, чи є URL скороченим
        result["is_short_url"] = self.is_short_url(url)
        if result["is_short_url"]:
            result["indicators"].append("short_url")
            result["risk_score"] += 0.4
        
        # Перевіряємо, чи є домен у базі шкідливих
        if domain in self.malicious_domains:
            result["is_malicious"] = True
            result["category"] = self.malicious_domains[domain]["category"]
            result["risk_score"] = 1.0
            result["indicators"].append("known_malicious")
            return result
        
        # Перевіряємо субдомени (для випадків типу google.login-secure.com)
        domain_parts = domain.split('.')
        for i in range(len(domain_parts) - 1):
            check_domain = '.'.join(domain_parts[i:])
            if check_domain in self.malicious_domains:
                result["is_malicious"] = True
                result["category"] = self.malicious_domains[check_domain]["category"]
                result["risk_score"] = 0.9
                result["indicators"].append("known_malicious_parent")
                return result
        
        # Перевіряємо ознаки підозрілих URL
        suspicious_indicators = 0
        for pattern in self.suspicious_url_indicators:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_indicators += 1
                result["indicators"].append(f"suspicious_pattern")
        
        # Визначаємо рівень підозрілості на основі кількості індикаторів
        if suspicious_indicators > 0:
            result["is_suspicious"] = True
            result["risk_score"] += min(0.8, 0.2 * suspicious_indicators)
        
        return result
    
    def check_urls_in_text(self, text: str) -> Dict[str, Any]:
        """
        Перевіряє всі URL в тексті
        """
        result = {
            "urls_found": [],
            "malicious_urls": [],
            "suspicious_urls": [],
            "short_urls": [],
            "risk_score": 0.0,
            "is_suspicious": False
        }
        
        # Витягуємо URL з тексту
        urls = self.extract_urls(text)
        if not urls:
            return result
            
        result["urls_found"] = urls
        
        # Перевіряємо кожен URL
        max_risk = 0.0
        total_risk = 0.0
        
        for url in urls:
            check_result = self.check_url(url)
            
            if check_result["is_malicious"]:
                result["malicious_urls"].append({
                    "url": url,
                    "domain": check_result["domain"],
                    "category": check_result["category"],
                    "risk_score": check_result["risk_score"],
                    "indicators": check_result["indicators"]
                })
                max_risk = max(max_risk, check_result["risk_score"])
                
            elif check_result["is_suspicious"]:
                result["suspicious_urls"].append({
                    "url": url,
                    "domain": check_result["domain"],
                    "risk_score": check_result["risk_score"],
                    "indicators": check_result["indicators"]
                })
                max_risk = max(max_risk, check_result["risk_score"])
                
            if check_result["is_short_url"]:
                result["short_urls"].append(url)
            
            total_risk += check_result["risk_score"]
        
        # Встановлюємо загальну оцінку ризику
        result["risk_score"] = max_risk if len(urls) == 1 else min(1.0, total_risk / len(urls) * 1.5)
        
        # Визначаємо, чи є текст підозрілим
        result["is_suspicious"] = (
            len(result["malicious_urls"]) > 0 or
            len(result["suspicious_urls"]) > 0 or
            (len(result["short_urls"]) > 0 and result["risk_score"] >= 0.3)
        )
        
        return result
    
    def add_malicious_domain(self, domain: str, category: str) -> bool:
        """
        Додає домен до бази шкідливих
        """
        try:
            # Нормалізуємо домен
            domain = domain.lower()
            
            # Завантажуємо поточний вміст файлу
            with open(self.malicious_domains_file, "r", encoding="utf-8") as f:
                domains_by_category = json.load(f)
            
            # Створюємо категорію, якщо вона не існує
            if category not in domains_by_category:
                domains_by_category[category] = []
            
            # Додаємо домен, якщо він ще не в списку
            if domain not in domains_by_category[category]:
                domains_by_category[category].append(domain)
                
                # Оновлюємо файл
                with open(self.malicious_domains_file, "w", encoding="utf-8") as f:
                    json.dump(domains_by_category, f, ensure_ascii=False, indent=2)
                
                # Оновлюємо внутрішній словник
                self.malicious_domains[domain] = {"category": category, "score": 1.0}
                
                logger.info(f"Домен '{domain}' додано до категорії '{category}'")
                return True
            else:
                logger.info(f"Домен '{domain}' вже є в категорії '{category}'")
                return False
                
        except Exception as e:
            logger.error(f"Помилка додавання шкідливого домену '{domain}': {e}")
            return False
    
    def remove_malicious_domain(self, domain: str) -> bool:
        """
        Видаляє домен з бази шкідливих
        """
        try:
            # Нормалізуємо домен
            domain = domain.lower()
            
            # Перевіряємо, чи існує домен у базі
            if domain not in self.malicious_domains:
                logger.warning(f"Домен '{domain}' не знайдено в базі шкідливих")
                return False
            
            # Завантажуємо поточний вміст файлу
            with open(self.malicious_domains_file, "r", encoding="utf-8") as f:
                domains_by_category = json.load(f)
            
            # Визначаємо категорію домену
            category = self.malicious_domains[domain]["category"]
            
            # Видаляємо домен зі списку
            if category in domains_by_category and domain in domains_by_category[category]:
                domains_by_category[category].remove(domain)
                
                # Оновлюємо файл
                with open(self.malicious_domains_file, "w", encoding="utf-8") as f:
                    json.dump(domains_by_category, f, ensure_ascii=False, indent=2)
                
                # Видаляємо з внутрішнього словника
                del self.malicious_domains[domain]
                
                logger.info(f"Домен '{domain}' видалено з бази шкідливих")
                return True
            else:
                logger.warning(f"Домен '{domain}' не знайдено в категорії '{category}'")
                return False
                
        except Exception as e:
            logger.error(f"Помилка видалення шкідливого домену '{domain}': {e}")
            return False