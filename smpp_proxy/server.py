import asyncio
import struct
import binascii
import uuid
from typing import Dict, Any, Optional, Union, Tuple, List, Callable, Set
import os
import sys
import argparse
import json

from logger.logger import SMPPLogger
from smpp_proxy.tls_config import TLSConfig, create_default_config
from smpp_proxy.secure_mode import SecureTransport, SecureSMPPProxy
from smpp_proxy.pdu_parser import PDUParser

# Імпортуємо компоненти детектора аномалій
from anomaly_detector.decision_engine.core import DecisionEngine
from storage.sqlite_client import SQLiteClient
from anomaly_detector.behavioral_analyzer.rate_limiter import rate_limiter, init_rate_limiter
from anomaly_detector.signature_analyzer.blacklists import blacklists_analyzer, init_blacklists_analyzer

logger = SMPPLogger("smpp_server")

class SMPPSession:
    """
    Клас для представлення сеансу SMPP клієнта на сервері
    """
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str
    ):
        self.reader = reader
        self.writer = writer
        self.session_id = session_id
        self.client_addr = writer.get_extra_info('peername')
        
        # Стан сеансу
        self.is_bound = False
        self.bind_type = None  # "transmitter", "receiver", "transceiver"
        self.system_id = None
        self.authorized = False
        
        # Лічильник пакетів
        self.packets_received = 0
        self.packets_sent = 0
        
        # Метадані
        self.metadata = {}
        
        logger.info(f"Новий SMPP сеанс {session_id} встановлено з {self.client_addr}")
    
    async def send_pdu(self, pdu_data: bytes) -> None:
        """
        Відправляє PDU клієнту
        """
        try:
            self.writer.write(pdu_data)
            await self.writer.drain()
            self.packets_sent += 1
            logger.debug(f"PDU відправлено клієнту {self.session_id}: {binascii.hexlify(pdu_data[:16]).decode()}")
        except Exception as e:
            logger.error(f"Помилка відправлення PDU клієнту {self.session_id}: {e}")
            raise
    
    async def read_pdu(self) -> bytes:
        """
        Читає PDU від клієнта
        """
        try:
            # Читаємо заголовок (4 байта для command_length)
            header = await self.reader.readexactly(4)
            command_length = int.from_bytes(header, byteorder='big')
            
            # Перевірка на розумне значення довжини
            if command_length < 16 or command_length > 1024 * 1024:  # Мінімум 16 байт, максимум 1 МБ
                logger.warning(f"Підозріла довжина команди від {self.session_id}: {command_length}")
                raise ValueError(f"Невалідна довжина PDU: {command_length}")
                
            # Читаємо решту PDU
            remaining = await self.reader.readexactly(command_length - 4)
            
            # Повне PDU
            pdu_data = header + remaining
            self.packets_received += 1
            
            return pdu_data
            
        except asyncio.IncompleteReadError as e:
            logger.error(f"З'єднання з {self.session_id} закрито при читанні PDU: {e}")
            raise
        except Exception as e:
            logger.error(f"Помилка читання PDU від {self.session_id}: {e}")
            raise
    
    async def close(self) -> None:
        """
        Закриває з'єднання з клієнтом
        """
        try:
            self.writer.close()
            await self.writer.wait_closed()
            logger.info(f"SMPP сеанс {self.session_id} закрито")
        except Exception as e:
            logger.error(f"Помилка закриття з'єднання з {self.session_id}: {e}")
    
    def get_info(self) -> Dict[str, Any]:
        """
        Повертає інформацію про сеанс
        """
        return {
            "session_id": self.session_id,
            "client_addr": self.client_addr,
            "is_bound": self.is_bound,
            "bind_type": self.bind_type,
            "system_id": self.system_id,
            "authorized": self.authorized,
            "packets_received": self.packets_received,
            "packets_sent": self.packets_sent,
            "metadata": self.metadata
        }


# Функція для аналізу PDU та виявлення аномалій
async def anomaly_detector_handler(pdu_data: bytes, direction: str, source: Any, destination: Any) -> Optional[bytes]:
    """
    Обробник для аналізу PDU на предмет аномалій
    """
    global decision_engine, pdu_parser, sqlite_client
    
    # Обробляємо лише пакети від клієнта до сервера і лише submit_sm
    if direction == "client_to_server":
        try:
            # Парсимо PDU
            parsed_pdu = pdu_parser.parse_pdu(pdu_data)
            
            # Перевіряємо, чи це submit_sm
            if parsed_pdu.get("command_name") == "submit_sm":
                # Витягуємо дані
                source_addr = parsed_pdu.get("source_addr", "")
                destination_addr = parsed_pdu.get("destination_addr", "")
                short_message = parsed_pdu.get("short_message", "")
                
                # Логуємо отримання повідомлення
                logger.info(f"Отримано повідомлення: від {source_addr} до {destination_addr}: {short_message[:30]}...")
                
                # Аналізуємо повідомлення
                result = await decision_engine.analyze(
                    message=short_message,
                    source_addr=source_addr,
                    destination_addr=destination_addr
                )
                
                # Обробляємо результат
                decision = result.get("decision", "allow")
                risk_score = result.get("risk_score", 0)
                tags = result.get("tags", [])
                
                # Зберігаємо результат в SQLite для подальшого аналізу
                try:
                    anomaly_data = {
                        "source": source_addr,
                        "dest": destination_addr,
                        "message": short_message,
                        "risk_score": risk_score,
                        "decision": decision,
                        "tags": tags
                    }
                    await sqlite_client.record_anomaly(anomaly_data)
                except Exception as e:
                    logger.error(f"Помилка запису аномалії в SQLite: {e}")
                
                if decision == "block":
                    # Логуємо блокування
                    logger.warning(
                        f"Заблоковано повідомлення від {source_addr} до {destination_addr}: "
                        f"risk_score={risk_score}, tags={tags}"
                    )
                    
                    # Явно викликаємо метод anomaly з правильними аргументами
                    logger.anomaly(
                        f"Заблоковано повідомлення",
                        source_addr,
                        destination_addr,
                        risk_score,
                        "blocked",
                        tags
                    )
                    
                    # Відправляємо помилку замість оригінального PDU
                    sequence_number = parsed_pdu.get("sequence_number", 0)
                    error_resp = struct.pack('!IIII',
                        16,                # command_length (тільки заголовок)
                        0x80000004,        # command_id (submit_sm_resp)
                        0x00000045,        # command_status (ESME_RREJECTMSG)
                        sequence_number    # sequence_number
                    )
                    
                    return error_resp
                    
                elif decision == "suspicious":
                    # Логуємо підозріле повідомлення
                    logger.warning(
                        f"Підозріле повідомлення від {source_addr} до {destination_addr}: "
                        f"risk_score={risk_score}, tags={tags}"
                    )
                    
                    # Явно викликаємо метод anomaly
                    logger.anomaly(
                        f"Підозріле повідомлення",
                        source_addr,
                        destination_addr,
                        risk_score,
                        "suspicious",
                        tags
                    )
                    
                    # Для підозрілих повідомлень все одно надсилаємо відповідь про успіх
                    sequence_number = parsed_pdu.get("sequence_number", 0)
                    message_id = b"test_message_id"
                    
                    resp_header = struct.pack('!IIII',
                        16 + 1 + len(message_id),  # command_length
                        0x80000004,                # command_id (submit_sm_resp)
                        0x00000000,                # command_status (OK)
                        sequence_number            # sequence_number
                    )
                    
                    resp_body = message_id + b'\x00'
                    
                    return resp_header + resp_body
                else:
                    # Логуємо дозволене повідомлення
                    logger.info(
                        f"Дозволено повідомлення від {source_addr} до {destination_addr}"
                    )
                    
                    # Явно викликаємо метод anomaly для дозволених повідомлень
                    logger.anomaly(
                        f"Дозволено повідомлення",
                        source_addr,
                        destination_addr,
                        risk_score,
                        "allowed",
                        tags
                    )
                    
                    # Для звичайних повідомлень надсилаємо відповідь про успіх
                    sequence_number = parsed_pdu.get("sequence_number", 0)
                    message_id = b"test_message_id"
                    
                    resp_header = struct.pack('!IIII',
                        16 + 1 + len(message_id),  # command_length
                        0x80000004,                # command_id (submit_sm_resp)
                        0x00000000,                # command_status (OK)
                        sequence_number            # sequence_number
                    )
                    
                    resp_body = message_id + b'\x00'
                    
                    return resp_header + resp_body
                
            # Обробка bind команд
            elif parsed_pdu.get("command_name") in ["bind_transmitter", "bind_receiver", "bind_transceiver"]:
                sequence_number = parsed_pdu.get("sequence_number", 0)
                command_id = parsed_pdu.get("command_id", 0)
                
                logger.info(f"Отримано команду {parsed_pdu.get('command_name')}, відправляємо відповідь")
                
                # Створюємо відповідь на bind
                resp_header = struct.pack('!IIII',
                    16,                       # command_length
                    command_id | 0x80000000,  # command_id (resp)
                    0x00000000,               # command_status (OK)
                    sequence_number           # sequence_number
                )
                
                return resp_header
            
            # Обробка unbind команди
            elif parsed_pdu.get("command_name") == "unbind":
                sequence_number = parsed_pdu.get("sequence_number", 0)
                
                # Створюємо відповідь на unbind
                resp_header = struct.pack('!IIII',
                    16,                # command_length
                    0x80000006,        # command_id (unbind_resp)
                    0x00000000,        # command_status (OK)
                    sequence_number    # sequence_number
                )
                
                return resp_header
                
        except Exception as e:
            logger.error(f"Помилка в обробнику аномалій: {e}")
    
    # За замовчуванням пропускаємо PDU без змін
    return pdu_data

async def init_components():
    """
    Ініціалізує основні компоненти системи
    """
    global sqlite_client, decision_engine, pdu_parser
    
    # Ініціалізуємо SQLite клієнт
    sqlite_client = SQLiteClient()
    await sqlite_client.connect()
    
    # Ініціалізуємо підсистеми, які використовують SQLite
    await init_rate_limiter()
    await init_blacklists_analyzer()
    
    # Ініціалізуємо парсер PDU
    pdu_parser = PDUParser()
    
    # Ініціалізуємо двигун прийняття рішень
    decision_engine = DecisionEngine()
    
    logger.info("Всі компоненти системи успішно ініціалізовано")

async def main():
    """
    Головна функція для запуску SMPP проксі з виявленням аномалій
    """
    global decision_engine, pdu_parser, sqlite_client
    
    parser = argparse.ArgumentParser(description="SMPP Anomaly Detector Server")
    
    parser.add_argument("--host", default="0.0.0.0", help="Хост для прослуховування")
    parser.add_argument("--port", type=int, default=2775, help="Порт для прослуховування")
    parser.add_argument("--remote-host", default="localhost", help="Віддалений SMPP хост")
    parser.add_argument("--remote-port", type=int, default=2776, help="Віддалений SMPP порт")
    
    parser.add_argument("--use-tls", action="store_true", help="Використовувати TLS")
    parser.add_argument("--cert-path", help="Шлях до сертифіката")
    parser.add_argument("--key-path", help="Шлях до приватного ключа")
    parser.add_argument("--no-tls", action="store_true", help="Не використовувати TLS (тестовий режим)")
    
    # Додаткові параметри для SQLite
    parser.add_argument("--sqlite-db", default=None, help="Шлях до бази даних SQLite")
    
    args = parser.parse_args()
    
    try:
        # Встановлюємо змінні оточення для SQLite, якщо вказані
        if args.sqlite_db:
            os.environ["SQLITE_DB_PATH"] = args.sqlite_db
        
        # Ініціалізуємо компоненти системи
        await init_components()
        
        # Налаштовуємо TLS, якщо потрібно
        tls_config = None
        
        if not args.no_tls and args.use_tls:
            tls_config = TLSConfig(
                cert_path=args.cert_path,
                key_path=args.key_path
            )
        
        # Створюємо проксі-сервер
        proxy = SecureSMPPProxy(
            listen_host=args.host,
            listen_port=args.port,
            remote_host=args.remote_host,
            remote_port=args.remote_port,
            tls_config=tls_config,
            client_requires_tls=args.use_tls and not args.no_tls,
            server_requires_tls=False
        )
        
        # Реєструємо обробник для аналізу PDU
        proxy.register_pdu_handler(anomaly_detector_handler)
        
        logger.info(
            f"Запуск SMPP проксі-сервера на {args.host}:{args.port} -> {args.remote_host}:{args.remote_port}, "
            f"TLS: {args.use_tls and not args.no_tls}, SQLite: {os.environ.get('SQLITE_DB_PATH', 'storage/anomaly_detector.db')}"
        )
        
        # Запускаємо проксі-сервер
        await proxy.start()
        
    except KeyboardInterrupt:
        logger.info("Сервер зупинено користувачем")
    except Exception as e:
        logger.error(f"Помилка запуску сервера: {e}")
    finally:
        # Закриваємо з'єднання з SQLite
        if sqlite_client:
            await sqlite_client.disconnect()

if __name__ == "__main__":
    # Глобальні змінні для обробника
    decision_engine = None
    pdu_parser = None
    sqlite_client = None
    
    asyncio.run(main())