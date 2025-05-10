import logging
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Налаштування логування
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Формат логу для файлу
file_handler = logging.FileHandler(f"{LOG_DIR}/smpp_log.jsonl")
file_handler.setLevel(logging.INFO)

# Формат логу для консолі
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Головний логер
logger = logging.getLogger("smpp_anomaly_detector")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class SMPPLogger:
    def __init__(self, component: str = "main"):
        self.component = component
        
    def _format_log(self, level: str, message: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "component": self.component,
            "level": level,
            "message": message
        }
        
        if extra:
            log_data.update(extra)
            
        return log_data
    
    def _write_json_log(self, log_data: Dict[str, Any]) -> None:
        with open(f"{LOG_DIR}/smpp_log.jsonl", "a") as f:
            f.write(json.dumps(log_data) + "\n")
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        log_data = self._format_log("INFO", message, extra)
        self._write_json_log(log_data)
        logger.info(message)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        log_data = self._format_log("WARNING", message, extra)
        self._write_json_log(log_data)
        logger.warning(message)
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        log_data = self._format_log("ERROR", message, extra)
        self._write_json_log(log_data)
        logger.error(message)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        log_data = self._format_log("DEBUG", message, extra)
        self._write_json_log(log_data)
        logger.debug(message)

    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        log_data = self._format_log("CRITICAL", message, extra)
        self._write_json_log(log_data)
        logger.critical(message)
        
    def anomaly(self, message: str, source: str, dest: str, risk_score: float, 
            decision: str, tags: list, extra: Optional[Dict[str, Any]] = None) -> None:
        """
        Спеціальний метод для логування виявлених аномалій
        """
        anomaly_data = {
            "source": source,
            "dest": dest,
            "risk_score": risk_score,
            "decision": decision,
            "tags": tags
        }
        
        if extra:
            anomaly_data.update(extra)
            
        log_data = self._format_log("ANOMALY", message, anomaly_data)
        self._write_json_log(log_data)
        logger.warning(f"ANOMALY: {message} - {json.dumps(anomaly_data)}")

# Створюємо екземпляр логера за замовчуванням
default_logger = SMPPLogger()
