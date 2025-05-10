import ssl
import os
from typing import Dict, Any, Optional, Tuple
from logging.logger import SMPPLogger

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
        
        logger.info(
            "Налаштування TLS ініціалізовано", 
            {
                "cert_path": self.cert_path,
                "key_path": self.key_path,
                "ca_certs": self.ca_certs,
                "verify_mode": self.verify_mode
            }
        )
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Створює налаштований контекст SSL
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = MIN_TLS_VERSION
            
            # Завантаження сертифікатів
            context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
            
            # Налаштування cipher suite
            context.set_ciphers(self.ciphers)
            
            # Налаштування перевірки клієнтського сертифікату
            context.verify_mode = self.verify_mode
            
            if self.ca_certs:
                context.load_verify_locations(cafile=self.ca_certs)
            
            # Додаткові налаштування безпеки
            context.options |= ssl.OP_NO_COMPRESSION
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            context.options |= ssl.OP_SINGLE_DH_USE
            context.options |= ssl.OP_SINGLE_ECDH_USE
            
            logger.info("SSL контекст успішно створено")
            return context
            
        except Exception as e:
            logger.error(f"Помилка створення SSL контексту: {e}")
            raise

    def create_client_ssl_context(self) -> ssl.SSLContext:
        """
        Створює налаштований контекст SSL для клієнта
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = MIN_TLS_VERSION
            
            # Налаштування cipher suite
            context.set_ciphers(self.ciphers)
            
            # Налаштування перевірки сертифікату сервера
            context.verify_mode = self.verify_mode
            
            if self.ca_certs:
                context.load_verify_locations(cafile=self.ca_certs)
            else:
                context.load_default_certs()
            
            logger.info("SSL клієнтський контекст успішно створено")
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
            "min_tls_version": MIN_TLS_VERSION.name
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
    Генерує самопідписаний сертифікат за допомогою OpenSSL
    Повертає шляхи до створених файлів сертифікату та ключа
    """
    try:
        # Створюємо директорію, якщо вона не існує
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        
        # Генеруємо приватний ключ
        openssl_cmd_key = (
            f"openssl genrsa -out {key_path} 2048"
        )
        os.system(openssl_cmd_key)
        
        # Генеруємо самопідписаний сертифікат
        openssl_cmd_cert = (
            f"openssl req -new -x509 -key {key_path} -out {cert_path} "
            f"-days {days_valid} -subj '/C={country}/ST={state}/L={locality}/"
            f"O={organization}/CN={common_name}'"
        )
        os.system(openssl_cmd_cert)
        
        logger.info(
            "Згенеровано самопідписаний сертифікат", 
            {"cert_path": cert_path, "key_path": key_path}
        )
        
        return cert_path, key_path
    except Exception as e:
        logger.error(f"Помилка генерації сертифікату: {e}")
        raise


# Функція для створення стандартного конфігу
def create_default_config() -> TLSConfig:
    """
    Створює TLS конфігурацію за замовчуванням
    Якщо сертифікати не існують, генерує самопідписані
    """
    # Перевіряємо, чи існують сертифікати
    if not (os.path.exists(DEFAULT_CERT_PATH) and os.path.exists(DEFAULT_KEY_PATH)):
        logger.warning("Сертифікати не знайдено, генеруємо самопідписані")
        generate_self_signed_cert()
    
    return TLSConfig()