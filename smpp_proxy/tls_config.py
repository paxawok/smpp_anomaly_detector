import ssl
import os
from typing import Dict, Any, Optional, Tuple
from logger.logger import SMPPLogger

logger = SMPPLogger("tls_config")

# Шляхи до сертифікатів за замовчуванням
DEFAULT_CERT_PATH = "crypto/certs/server.crt"
DEFAULT_KEY_PATH = "crypto/certs/server.key"

# Безпечні параметри TLS
SECURE_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
)

# Мінімальна версія TLS
MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2


class TLSConfig:
    def __init__(
        self,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        ca_certs: Optional[str] = None,
        ciphers: Optional[str] = None,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
    ):
        self.cert_path = cert_path or os.environ.get("TLS_CERT_PATH", DEFAULT_CERT_PATH)
        self.key_path = key_path or os.environ.get("TLS_KEY_PATH", DEFAULT_KEY_PATH)
        self.ca_certs = ca_certs or os.environ.get("TLS_CA_CERTS")
        self.ciphers = ciphers or os.environ.get("TLS_CIPHERS", SECURE_CIPHERS)
        self.verify_mode = verify_mode
        
        # Для тестування в пам'яті
        self.test_mode = True
        
        logger.info(
            "Налаштування TLS ініціалізовано (тестовий режим)", 
            {
                "cert_path": self.cert_path,
                "key_path": self.key_path,
                "ca_certs": self.ca_certs,
                "verify_mode": self.verify_mode
            }
        )
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Створює налаштований контекст SSL (тестовий режим)
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = MIN_TLS_VERSION
            
            # Вимикаємо перевірку для тестування
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Додаткові налаштування безпеки
            context.options |= ssl.OP_NO_COMPRESSION
            
            logger.info("SSL контекст успішно створено (тестовий режим)")
            return context
            
        except Exception as e:
            logger.error(f"Помилка створення SSL контексту: {e}")
            raise

    def create_client_ssl_context(self) -> ssl.SSLContext:
        """
        Створює налаштований контекст SSL для клієнта (тестовий режим)
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = MIN_TLS_VERSION
            
            # Вимикаємо перевірку для тестування
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            logger.info("SSL клієнтський контекст успішно створено (тестовий режим)")
            return context
            
        except Exception as e:
            logger.error(f"Помилка створення SSL клієнтського контексту: {e}")
            raise
            
    def get_config_dict(self) -> Dict[str, Any]:
        """
        Повертає словник з поточними налаштуваннями
        """
        return {
            "cert_path": self.cert_path,
            "key_path": self.key_path,
            "ca_certs": self.ca_certs,
            "ciphers": self.ciphers,
            "verify_mode": self.verify_mode,
            "min_tls_version": MIN_TLS_VERSION.name,
            "test_mode": self.test_mode
        }

# Функція для генерування самопідписаних сертифікатів (для розробки)
def generate_self_signed_cert(
    cert_path: str = DEFAULT_CERT_PATH,
    key_path: str = DEFAULT_KEY_PATH,
    country: str = "UA",
    state: str = "Kyiv",
    locality: str = "Kyiv",
    organization: str = "SMPP Anomaly Detector",
    common_name: str = "localhost",
    days_valid: int = 365
) -> Tuple[str, str]:
    """
    Симулює генерацію самопідписаних сертифікатів для тестування.
    У тестовому режимі не створює реальні файли.
    """
    try:
        logger.info("Симуляція генерації сертифікатів для тестування")
        return cert_path, key_path
    except Exception as e:
        logger.error(f"Помилка при симуляції генерації сертифікатів: {e}")
        return cert_path, key_path

# Функція для створення стандартного конфігу
def create_default_config() -> TLSConfig:
    """
    Створює TLS конфігурацію за замовчуванням для тестового режиму
    """
    return TLSConfig()
