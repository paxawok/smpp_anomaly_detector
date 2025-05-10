import ssl
import socket
import asyncio
from typing import Any, Callable, Coroutine, Dict, Optional, Tuple, Union

from logging.logger import SMPPLogger
from smpp_proxy.tls_config import TLSConfig, create_default_config

logger = SMPPLogger("secure_mode")

class SecureTransport:
    """
    Клас для забезпечення TLS/SSL транспорту для SMPP з'єднань
    """
    def __init__(
        self,
        tls_config: Optional[TLSConfig] = None,
        server_mode: bool = True
    ):
        self.tls_config = tls_config or create_default_config()
        self.server_mode = server_mode
        
        # Створюємо відповідний SSL контекст
        if server_mode:
            self.ssl_context = self.tls_config.create_ssl_context()
        else:
            self.ssl_context = self.tls_config.create_client_ssl_context()
        
        logger.info(
            f"SecureTransport ініціалізовано в режимі {'сервера' if server_mode else 'клієнта'}"
        )
        
    async def wrap_socket(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Обгортає існуюче TCP з'єднання в TLS/SSL
        Цей метод просто повертає вже захищений сокет в режимі сервера,
        в режимі клієнта використовуйте open_connection
        """
        if not self.server_mode:
            logger.warning("wrap_socket викликаний у режимі клієнта, це може не працювати коректно")
        
        return reader, writer
    
    async def open_connection(
        self,
        host: str,
        port: int
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Відкриває нове захищене з'єднання до віддаленого хоста
        """
        try:
            reader, writer = await asyncio.open_connection(
                host=host,
                port=port,
                ssl=self.ssl_context if not self.server_mode else None
            )
            
            logger.info(f"Захищене з'єднання встановлено з {host}:{port}")
            return reader, writer
            
        except Exception as e:
            logger.error(f"Помилка встановлення захищеного з'єднання з {host}:{port}: {e}")
            raise
    
    async def start_server(
        self,
        client_connected_cb: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, None]],
        host: str,
        port: int
    ) -> asyncio.Server:
        """
        Запускає захищений сервер
        """
        try:
            server = await asyncio.start_server(
                client_connected_cb,
                host=host,
                port=port,
                ssl=self.ssl_context if self.server_mode else None
            )
            
            logger.info(f"Захищений сервер запущено на {host}:{port}")
            return server
            
        except Exception as e:
            logger.error(f"Помилка запуску захищеного сервера на {host}:{port}: {e}")
            raise


class SecureSMPPSession:
    """
    Клас для обробки захищеного SMPP сеансу
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
        self.remote_addr = writer.get_extra_info('peername')
        
        # Статус з'єднання
        self.is_bound = False
        self.bind_type = None  # "transmitter", "receiver", "transceiver"
        self.system_id = None
        
        logger.info(f"Створено новий SMPP сеанс {self.session_id} з {self.remote_addr}")
    
    async def read_pdu(self) -> bytes:
        """
        Читає PDU з потоку
        """
        try:
            # Читаємо заголовок (4 байта для command_length)
            header = await self.reader.readexactly(4)
            command_length = int.from_bytes(header, byteorder='big')
            
            # Перевірка на розумне значення довжини
            if command_length < 16 or command_length > 1024 * 1024:  # Мінімум 16 байт, максимум 1 МБ
                logger.warning(f"Підозріла довжина команди: {command_length}")
                raise ValueError(f"Невалідна довжина PDU: {command_length}")
                
            # Читаємо решту PDU
            remaining = await self.reader.readexactly(command_length - 4)
            
            # Повертаємо повне PDU
            return header + remaining
            
        except asyncio.IncompleteReadError as e:
            logger.error(f"Помилка читання PDU: з'єднання закрито {e}")
            raise
        except Exception as e:
            logger.error(f"Помилка читання PDU: {e}")
            raise
            
    async def write_pdu(self, data: bytes) -> None:
        """
        Записує PDU у потік
        """
        try:
            self.writer.write(data)
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Помилка запису PDU: {e}")
            raise
            
    async def close(self) -> None:
        """
        Закриває з'єднання
        """
        try:
            self.writer.close()
            await self.writer.wait_closed()
            logger.info(f"SMPP сеанс {self.session_id} закрито")
        except Exception as e:
            logger.error(f"Помилка закриття з'єднання: {e}")


class SecureSMPPProxy:
    """
    Проксі-сервер для SMPP, який забезпечує TLS/SSL та перенаправлення трафіку
    """
    def __init__(
        self, 
        listen_host: str,
        listen_port: int,
        remote_host: str,
        remote_port: int,
        tls_config: Optional[TLSConfig] = None,
        client_requires_tls: bool = True,
        server_requires_tls: bool = False
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        
        # Налаштування TLS
        self.tls_config = tls_config or create_default_config()
        self.client_requires_tls = client_requires_tls
        self.server_requires_tls = server_requires_tls
        
        # Транспорт для з'єднань
        self.server_transport = SecureTransport(self.tls_config, server_mode=True)
        self.client_transport = SecureTransport(self.tls_config, server_mode=False)
        
        # Запущений сервер
        self.server = None
        
        # Сесії
        self.sessions = {}
        
        # Обробники повідомлень
        self.pdu_handlers = []
        
        logger.info(
            f"SMPP проксі ініціалізовано: {listen_host}:{listen_port} -> {remote_host}:{remote_port}",
            {
                "client_requires_tls": client_requires_tls,
                "server_requires_tls": server_requires_tls
            }
        )
        
    def register_pdu_handler(self, handler: Callable) -> None:
        """
        Реєструє обробник для PDU
        """
        self.pdu_handlers.append(handler)
        logger.info(f"Зареєстровано обробник PDU: {handler.__name__}")
        
    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        """
        Обробляє з'єднання клієнта
        """
        # Створюємо унікальний ID сесії
        session_id = f"session_{id(client_reader)}"
        client_addr = client_writer.get_extra_info('peername')
        
        logger.info(f"Нове з'єднання від: {client_addr}, сесія: {session_id}")
        
        try:
            # Створюємо сесію клієнта
            client_session = SecureSMPPSession(client_reader, client_writer, session_id)
            
            # Підключаємось до віддаленого сервера
            remote_reader, remote_writer = await self.client_transport.open_connection(
                self.remote_host, self.remote_port
            )
            
            # Створюємо сесію сервера
            server_session = SecureSMPPSession(remote_reader, remote_writer, f"{session_id}_server")
            
            # Зберігаємо сесії
            self.sessions[session_id] = {
                "client": client_session,
                "server": server_session,
                "start_time": asyncio.get_event_loop().time()
            }
            
            # Запускаємо два напрямки проксі
            client_to_server = asyncio.create_task(
                self._proxy_data(client_session, server_session, "client_to_server")
            )
            server_to_client = asyncio.create_task(
                self._proxy_data(server_session, client_session, "server_to_client")
            )
            
            # Чекаємо завершення будь-якого з напрямків
            done, pending = await asyncio.wait(
                [client_to_server, server_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Скасовуємо залишені завдання
            for task in pending:
                task.cancel()
                
            # Закриваємо сесії
            await client_session.close()
            await server_session.close()
            
            # Видаляємо сесію
            del self.sessions[session_id]
            logger.info(f"Сесія {session_id} завершена")
            
        except Exception as e:
            logger.error(f"Помилка обробки клієнта {client_addr}: {e}")
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except:
                pass
    
    async def _proxy_data(
        self, 
        source: SecureSMPPSession, 
        destination: SecureSMPPSession, 
        direction: str
    ) -> None:
        """
        Проксі даних від source до destination
        """
        try:
            while True:
                # Читаємо PDU з джерела
                pdu_data = await source.read_pdu()
                
                # Викликаємо обробники PDU
                for handler in self.pdu_handlers:
                    pdu_data = await handler(pdu_data, direction, source, destination)
                    if pdu_data is None:
                        logger.info(f"PDU заблоковано обробником {handler.__name__}")
                        break
                
                # Якщо PDU не заблоковано, відправляємо його
                if pdu_data:
                    await destination.write_pdu(pdu_data)
                    
        except asyncio.CancelledError:
            logger.info(f"Проксі-завдання {direction} скасовано")
        except Exception as e:
            logger.error(f"Помилка проксі {direction}: {e}")
    
    async def start(self) -> None:
        """
        Запускає SMPP проксі-сервер
        """
        try:
            self.server = await self.server_transport.start_server(
                self.handle_client,
                self.listen_host,
                self.listen_port
            )
            
            addr = self.server.sockets[0].getsockname()
            logger.info(f"SMPP проксі-сервер запущено на {addr}")
            
            # Очікуємо серверне завдання
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            logger.error(f"Помилка запуску SMPP проксі-сервера: {e}")
            raise
            
    def stop(self) -> None:
        """
        Зупиняє SMPP проксі-сервер
        """
        if self.server:
            self.server.close()
            logger.info("SMPP проксі-сервер зупинено")