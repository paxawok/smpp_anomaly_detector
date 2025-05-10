import json
import os
import asyncio
from typing import Dict, List, Tuple, Any, Optional, Set, Union

from logger.logger import SMPPLogger

# Імпортуємо аналізатори
from anomaly_detector.content_analyzer.text_checker import TextChecker
from anomaly_detector.content_analyzer.url_checker import URLChecker
from anomaly_detector.signature_analyzer.blacklists import BlacklistsAnalyzer
from anomaly_detector.signature_analyzer.geo_checker import GeoChecker
from anomaly_detector.behavioral_analyzer.rate_limiter import RateLimiter

logger = SMPPLogger("decision_engine")

class DecisionEngine:
    """
    Головний клас системи прийняття рішень на основі різних видів аналізу
    """
    def __init__(
        self, 
        config_file: Optional[str] = None,
        text_checker: Optional[TextChecker] = None,
        url_checker: Optional[URLChecker] = None,
        blacklists_analyzer: Optional[BlacklistsAnalyzer] = None,
        geo_checker: Optional[GeoChecker] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        # Шлях до файлу конфігурації
        self.config_file = config_file or os.path.join(
            os.path.dirname(__file__), "config", "decision_config.json"
        )
        
        # Завантажуємо конфігурацію
        self.config = self._load_config()
        
        # Ініціалізуємо аналізатори
        self.text_checker = text_checker or TextChecker()
        self.url_checker = url_checker or URLChecker()
        self.blacklists_analyzer = blacklists_analyzer or BlacklistsAnalyzer()
        self.geo_checker = geo_checker or GeoChecker()
        self.rate_limiter = rate_limiter or RateLimiter()
        
        # Рішення за замовчуванням
        self.default_decision = self.config.get("default_decision", "allow")
        
        # Порогові значення для прийняття рішень
        self.thresholds = self.config.get("thresholds", {
            "block": 0.8,      # Блокувати, якщо оцінка ризику >= 0.8
            "suspicious": 0.5,  # Підозріло, якщо оцінка ризику >= 0.5
            "allow": 0.0       # Дозволити, якщо оцінка ризику < 0.5
        })
        
        # Ваги для різних типів аналізу
        self.weights = self.config.get("weights", {
            "content": 1.0,
            "url": 1.0,
            "blacklist": 1.0,
            "geo": 1.0,
            "rate": 0.7
        })
        
        logger.info("DecisionEngine ініціалізовано")
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Завантажує конфігурацію з файлу
        """
        try:
            # Створюємо директорію для конфігурації, якщо вона не існує
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            # Якщо файл не існує, створюємо його з налаштуваннями за замовчуванням
            if not os.path.exists(self.config_file):
                default_config = {
                    "default_decision": "allow",
                    "thresholds": {
                        "block": 0.8,
                        "suspicious": 0.5,
                        "allow": 0.0
                    },
                    "weights": {
                        "content": 1.0,
                        "url": 1.0,
                        "blacklist": 1.0,
                        "geo": 1.0,
                        "rate": 0.7
                    },
                    "override_rules": [
                        {
                            "condition": "blacklist.is_blacklisted",
                            "decision": "block"
                        },
                        {
                            "condition": "geo.is_blocked",
                            "decision": "block"
                        },
                        {
                            "condition": "url.is_malicious",
                            "decision": "block"
                        }
                    ]
                }
                
                with open(self.config_file, "w", encoding="utf-8") as f:
                    json.dump(default_config, f, ensure_ascii=False, indent=2)
                
                return default_config
            
            # Інакше завантажуємо існуючий файл
            with open(self.config_file, "r", encoding="utf-8") as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Помилка завантаження конфігурації: {e}")
            # Повертаємо конфігурацію за замовчуванням у випадку помилки
            return {
                "default_decision": "allow",
                "thresholds": {
                    "block": 0.8,
                    "suspicious": 0.5,
                    "allow": 0.0
                },
                "weights": {
                    "content": 1.0,
                    "url": 1.0,
                    "blacklist": 1.0,
                    "geo": 1.0,
                    "rate": 0.7
                },
                "override_rules": []
            }
    
    async def analyze(
        self, 
        message: str, 
        source_addr: str, 
        destination_addr: str
    ) -> Dict[str, Any]:
        """
        Проводить повний аналіз повідомлення і повертає рішення
        """
        result = {
            "message": message,
            "source_addr": source_addr,
            "destination_addr": destination_addr,
            "risk_score": 0.0,
            "decision": self.default_decision,
            "tags": [],
            "analysis": {}
        }
        
        try:
            # Аналіз контенту
            content_result = self.text_checker.check_text(message)
            result["analysis"]["content"] = content_result
            
            if content_result["suspicious"]:
                for tag in content_result["tags"]:
                    if tag not in result["tags"]:
                        result["tags"].append(tag)
            
            # Аналіз URL
            url_result = self.url_checker.check_urls_in_text(message)
            result["analysis"]["url"] = url_result
            
            if url_result["is_suspicious"]:
                if "suspicious_url" not in result["tags"]:
                    result["tags"].append("suspicious_url")
                
                if "short_url" not in result["tags"] and url_result["short_urls"]:
                    result["tags"].append("short_url")
                
                if "malicious_url" not in result["tags"] and url_result["malicious_urls"]:
                    result["tags"].append("malicious_url")
            
            # Аналіз джерела (чорний список)
            blacklist_result = self.blacklists_analyzer.check_sender(source_addr)
            result["analysis"]["blacklist"] = blacklist_result
            
            if blacklist_result["is_blacklisted"]:
                if "blacklisted_sender" not in result["tags"]:
                    result["tags"].append("blacklisted_sender")
            
            # Аналіз повідомлення на наявність шаблонів
            pattern_result = self.blacklists_analyzer.check_message_content(message)
            result["analysis"]["pattern"] = pattern_result
            
            if pattern_result["is_suspicious"]:
                for category in pattern_result["categories"]:
                    if category not in result["tags"]:
                        result["tags"].append(category)
            
            # Аналіз географії
            geo_result = self.geo_checker.check_phone(destination_addr)
            result["analysis"]["geo"] = geo_result
            
            if geo_result["is_blocked"]:
                if "blocked_region" not in result["tags"]:
                    result["tags"].append("blocked_region")
                
                if geo_result["category"] not in result["tags"]:
                    result["tags"].append(geo_result["category"])
            
            # Аналіз частоти
            rate_result = await self.rate_limiter.check_rate_limit(source_addr, destination_addr)
            result["analysis"]["rate"] = rate_result
            
            if rate_result["exceeded"]:
                if "rate_limit_exceeded" not in result["tags"]:
                    result["tags"].append("rate_limit_exceeded")
            
            # Обчислюємо загальну оцінку ризику
            weighted_scores = [
                content_result["risk_score"] * self.weights.get("content", 1.0),
                url_result["risk_score"] * self.weights.get("url", 1.0),
                blacklist_result["risk_score"] * self.weights.get("blacklist", 1.0),
                pattern_result["risk_score"] * self.weights.get("pattern", 1.0),
                geo_result["risk_score"] * self.weights.get("geo", 1.0),
                rate_result["risk_score"] * self.weights.get("rate", 0.7)
            ]
            
            # Вибираємо максимальну зважену оцінку
            result["risk_score"] = max(weighted_scores)
            
            # Застосовуємо правила перевизначення
            override_decision = self._apply_override_rules(result)
            if override_decision:
                result["decision"] = override_decision
            else:
                # Визначаємо рішення на основі оцінки ризику
                result["decision"] = self._get_decision_from_score(result["risk_score"])
            
            # Логуємо результат
            if result["decision"] != "allow":
                logger.warning(
                    f"Виявлено аномалію: {result['decision']}, score: {result['risk_score']:.2f}, tags: {result['tags']}",
                    {
                        "source": source_addr,
                        "dest": destination_addr,
                        "risk_score": result["risk_score"],
                        "decision": result["decision"],
                        "tags": result["tags"]
                    }
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Помилка аналізу повідомлення: {e}")
            # У випадку помилки аналізу повертаємо результат за замовчуванням
            result["risk_score"] = 0.0
            result["decision"] = "allow"
            result["error"] = str(e)
            return result
    
    def _apply_override_rules(self, result: Dict[str, Any]) -> Optional[str]:
        """
        Застосовує правила перевизначення
        Повертає рішення, якщо правило застосовано, інакше None
        """
        for rule in self.config.get("override_rules", []):
            condition = rule.get("condition")
            if not condition:
                continue
                
            # Розбиваємо умову на частини (наприклад, "blacklist.is_blacklisted")
            parts = condition.split(".")
            if len(parts) != 2:
                continue
                
            analysis_type, field = parts
            
            # Отримуємо результат аналізу для заданого типу
            analysis_result = result["analysis"].get(analysis_type)
            if not analysis_result:
                continue
                
            # Перевіряємо умову
            if analysis_result.get(field, False):
                return rule.get("decision", self.default_decision)
        
        return None
    
    def _get_decision_from_score(self, score: float) -> str:
        """
        Визначає рішення на основі оцінки ризику
        """
        if score >= self.thresholds.get("block", 0.8):
            return "block"
        elif score >= self.thresholds.get("suspicious", 0.5):
            return "suspicious"
        else:
            return "allow"
    
    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """
        Оновлює конфігурацію системи прийняття рішень
        """
        try:
            # Оновлюємо поля конфігурації, які присутні в new_config
            for key, value in new_config.items():
                if key in self.config:
                    if isinstance(value, dict) and isinstance(self.config[key], dict):
                        # Для вкладених словників оновлюємо поелементно
                        for sub_key, sub_value in value.items():
                            self.config[key][sub_key] = sub_value
                    else:
                        # Для простих значень просто замінюємо
                        self.config[key] = value
            
            # Зберігаємо оновлену конфігурацію
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            
            # Оновлюємо поля класу
            self.default_decision = self.config.get("default_decision", "allow")
            self.thresholds = self.config.get("thresholds", {
                "block": 0.8,
                "suspicious": 0.5,
                "allow": 0.0
            })
            self.weights = self.config.get("weights", {
                "content": 1.0,
                "url": 1.0,
                "blacklist": 1.0,
                "geo": 1.0,
                "rate": 0.7
            })
            
            logger.info(f"Конфігурацію DecisionEngine оновлено: {json.dumps(self.config)}")
            return True
            
        except Exception as e:
            logger.error(f"Помилка оновлення конфігурації: {e}")
            return False
