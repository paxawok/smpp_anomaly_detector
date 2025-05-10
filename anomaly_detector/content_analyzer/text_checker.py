import re
import os
import json
import Levenshtein
from typing import Dict, List, Tuple, Set, Any, Optional

from logger.logger import SMPPLogger

logger = SMPPLogger("text_checker")

class TextChecker:
    """
    Клас для аналізу текстового вмісту SMS на предмет аномалій
    """
    def __init__(self, keywords_file: Optional[str] = None):
        self.keywords_file = keywords_file or os.path.join(
            os.path.dirname(__file__), "data", "keywords.json"
        )
        
        # Завантажуємо ключові слова
        self.keywords = self._load_keywords()
        
        # Патерни для обфускованих слів
        self.obfuscation_patterns = {
            "a": "[a@4аа]",
            "b": "[b6вь]",
            "c": "[csсc]",
            "e": "[eе3]",
            "i": "[i1lі]",
            "o": "[o0оо]",
            "s": "[s5$]",
            "t": "[t7т]",
            "l": "[l1і]",
            "n": "[nп]",
            "m": "[mм]",
            "h": "[hн]",
            "p": "[pр]",
            "y": "[yу]",
            "x": "[xх]",
            "k": "[kк]"
        }
        
        logger.info(f"TextChecker ініціалізовано з {len(self.keywords)} ключовими словами")
        
    def _load_keywords(self) -> Dict[str, Dict[str, Any]]:
        """
        Завантажує ключові слова з JSON файлу
        """
        try:
            # Створюємо директорію, якщо вона не існує
            os.makedirs(os.path.dirname(self.keywords_file), exist_ok=True)
            
            # Якщо файл не існує, створюємо його з базовими ключовими словами
            if not os.path.exists(self.keywords_file):
                default_keywords = {
                    "phishing": {
                        "keywords": [
                            "password", "пароль", "verify", "verification", "account", 
                            "security", "blocked", "verify", "безпека", "bank", "банк",
                            "credit", "card", "картка", "monobank", "приватбанк", "verify",
                            "code", "код", "activate", "update", "urgent", "терміново"
                        ],
                        "weight": 0.7,
                        "threshold": 2
                    },
                    "spam": {
                        "keywords": [
                            "free", "bonus", "discount", "sale", "offer", "promocode", 
                            "бесплатно", "акція", "знижка", "розпродаж", "пропозиція",
                            "промокод", "скидка", "выгода", "спеццена", "успей"
                        ],
                        "weight": 0.4,
                        "threshold": 3
                    },
                    "fraud": {
                        "keywords": [
                            "win", "prize", "lottery", "lucky", "money", "cash",
                            "виграш", "приз", "лотерея", "гроші", "jackpot", 
                            "congratulations", "вітаємо", "поздравляем", "casino",
                            "казино", "betting", "ставки", "sports betting"
                        ],
                        "weight": 0.6,
                        "threshold": 2
                    },
                    "adult": {
                        "keywords": [
                            "adult", "xxx", "sex", "dating", "18+", "hot", "sexy",
                            "знакомства", "побачення", "date", "intimate"
                        ],
                        "weight": 0.5,
                        "threshold": 2
                    }
                }
                
                with open(self.keywords_file, "w", encoding="utf-8") as f:
                    json.dump(default_keywords, f, ensure_ascii=False, indent=2)
                
                return default_keywords
            
            # Інакше завантажуємо існуючий файл
            with open(self.keywords_file, "r", encoding="utf-8") as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Помилка завантаження ключових слів: {e}")
            # Повертаємо пустий словник у випадку помилки
            return {}
    
    def is_obfuscated(self, text: str, keywords: List[str], threshold: float = 0.75) -> Tuple[bool, Optional[str]]:
        """
        Перевіряє, чи містить текст обфусковані версії ключових слів
        Повертає (знайдено, ключове_слово)
        """
        # Приводимо текст до нижнього регістру
        text = text.lower()
        
        # Для кожного ключового слова
        for keyword in keywords:
            # Нормалізуємо ключове слово (нижній регістр)
            keyword_lower = keyword.lower()
            
            # Пряме співпадіння
            if keyword_lower in text:
                return True, keyword
            
            # Перевіряємо схожість за допомогою відстані Левенштейна
            for word in text.split():
                if len(word) > 2 and len(keyword_lower) > 2:
                    # Обчислюємо відстань
                    distance = Levenshtein.distance(word, keyword_lower)
                    max_len = max(len(word), len(keyword_lower))
                    similarity = 1 - (distance / max_len)
                    
                    if similarity >= threshold:
                        return True, keyword
            
            # Генеруємо регулярний вираз для обфускованого ключового слова
            try:
                pattern = ""
                for char in keyword_lower:
                    if char in self.obfuscation_patterns:
                        pattern += self.obfuscation_patterns[char]
                    else:
                        pattern += char
                
                # Пошук за регулярним виразом
                if re.search(rf"\b{pattern}\b", text):
                    return True, keyword
            except Exception as e:
                logger.error(f"Помилка при створенні регулярного виразу для {keyword}: {e}")
            
        return False, None
    
    def check_text(self, text: str) -> Dict[str, Any]:
        """
        Перевіряє текст на наявність підозрілих ключових слів та обфускації
        Повертає словник з результатами перевірки
        """
        results = {
            "categories": {},
            "obfuscation_detected": False,
            "risk_score": 0.0,
            "suspicious": False,
            "tags": []
        }
        
        if not text or len(text) < 3:
            return results
        
        # Приводимо текст до нижнього регістру
        text_lower = text.lower()
        
        total_score = 0.0
        max_weight = 0.0
        
        # Проходимо по категоріям ключових слів
        for category, config in self.keywords.items():
            keywords = config.get("keywords", [])
            weight = config.get("weight", 0.5)
            threshold = config.get("threshold", 1)
            
            found_keywords = []
            
            # Перевіряємо наявність ключових слів
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    found_keywords.append(keyword)
            
            # Перевіряємо обфускацію
            is_obfuscated, obfuscated_keyword = self.is_obfuscated(text, keywords)
            if is_obfuscated and obfuscated_keyword not in found_keywords:
                found_keywords.append(obfuscated_keyword)
                results["obfuscation_detected"] = True
                if "obfuscation" not in results["tags"]:
                    results["tags"].append("obfuscation")
            
            # Якщо знайдено достатньо ключових слів
            if len(found_keywords) >= threshold:
                # Розраховуємо оцінку ризику для категорії
                category_score = weight * (len(found_keywords) / len(keywords))
                
                # Оновлюємо загальну оцінку
                total_score += category_score
                max_weight = max(max_weight, weight)
                
                # Зберігаємо результати для категорії
                results["categories"][category] = {
                    "found_keywords": found_keywords,
                    "score": category_score,
                    "suspicious": True
                }
                
                # Додаємо категорію до тегів
                if category not in results["tags"]:
                    results["tags"].append(category)
            else:
                # Категорія не підозріла
                results["categories"][category] = {
                    "found_keywords": found_keywords,
                    "score": 0.0,
                    "suspicious": False
                }
        
        # Нормалізуємо загальну оцінку ризику
        if max_weight > 0:
            results["risk_score"] = min(total_score / max_weight, 1.0)
        
        # Визначаємо, чи є текст підозрілим
        results["suspicious"] = results["risk_score"] >= 0.5 or results["obfuscation_detected"]
        
        return results
    
    def check_bank_names(self, text: str) -> Dict[str, Any]:
        """
        Перевіряє наявність назв банків у тексті
        Може бути використано для виявлення фішингу
        """
        bank_names = [
            "monobank", "privatbank", "oschadbank", "ukrsibbank", "raiffeisen",
            "приватбанк", "ощадбанк", "укрсиббанк", "райффайзен", "монобанк",
            "аваль", "альфа-банк", "укрексімбанк", "credit agricole", "укргазбанк",
            "ощад", "приват", "моно", "моно банк", "пумб"
        ]
        
        results = {
            "bank_names_found": [],
            "risk_score": 0.0,
            "suspicious": False
        }
        
        # Приводимо текст до нижнього регістру
        text_lower = text.lower()
        
        # Шукаємо банки в тексті
        for bank in bank_names:
            if bank.lower() in text_lower:
                results["bank_names_found"].append(bank)
                
            # Перевіряємо на обфускацію
            is_obfuscated, obfuscated_bank = self.is_obfuscated(text, [bank])
            if is_obfuscated and obfuscated_bank not in results["bank_names_found"]:
                results["bank_names_found"].append(obfuscated_bank)
        
        # Оцінюємо ризик
        if results["bank_names_found"]:
            results["risk_score"] = 0.7
            results["suspicious"] = True
        
        return results
    
    def add_keywords(self, category: str, keywords: List[str], weight: Optional[float] = None, threshold: Optional[int] = None) -> bool:
        """
        Додає нові ключові слова до категорії
        """
        try:
            if category not in self.keywords:
                self.keywords[category] = {
                    "keywords": [],
                    "weight": weight or 0.5,
                    "threshold": threshold or 1
                }
            
            # Оновлюємо вагу та поріг, якщо вони вказані
            if weight is not None:
                self.keywords[category]["weight"] = weight
                
            if threshold is not None:
                self.keywords[category]["threshold"] = threshold
            
            # Додаємо нові ключові слова
            current_keywords = set(self.keywords[category]["keywords"])
            for keyword in keywords:
                if keyword not in current_keywords:
                    self.keywords[category]["keywords"].append(keyword)
                    current_keywords.add(keyword)
            
            # Зберігаємо оновлений файл
            with open(self.keywords_file, "w", encoding="utf-8") as f:
                json.dump(self.keywords, f, ensure_ascii=False, indent=2)
                
            logger.info(f"Додано {len(keywords)} ключових слів до категорії '{category}'")
            return True
            
        except Exception as e:
            logger.error(f"Помилка додавання ключових слів до категорії '{category}': {e}")
            return False
    
    def remove_keywords(self, category: str, keywords: List[str]) -> bool:
        """
        Видаляє ключові слова з категорії
        """
        try:
            if category not in self.keywords:
                logger.warning(f"Категорія '{category}' не існує")
                return False
            
            # Видаляємо ключові слова
            removed = 0
            for keyword in keywords:
                if keyword in self.keywords[category]["keywords"]:
                    self.keywords[category]["keywords"].remove(keyword)
                    removed += 1
            
            # Зберігаємо оновлений файл
            with open(self.keywords_file, "w", encoding="utf-8") as f:
                json.dump(self.keywords, f, ensure_ascii=False, indent=2)
                
            logger.info(f"Видалено {removed} ключових слів з категорії '{category}'")
            return True
            
        except Exception as e:
            logger.error(f"Помилка видалення ключових слів з категорії '{category}': {e}")
            return False
