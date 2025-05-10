import asyncio
import struct
import binascii
import random
from typing import Dict, Any, Optional, Union, Tuple, List, Callable

from logger.logger import SMPPLogger
from smpp_proxy.tls_config import TLSConfig
from smpp_proxy.secure_mode import SecureTransport
from smpp_proxy.pdu_parser import PDUParser

logger = SMPPLogger("smpp_client")

class SMPPClient:
    """
    Асинхронний SMPP клієнт з підтримкою TLS
    """
    def __init__(
        self,
        host: str,
        port: int,
        system_id: str,
        password: str,
        system_type: str = "",
        use_tls: bool = False,
        tls_config: Optional[TLSConfig] = None,
        pdu_parser: Optional[PDUParser] = None
    ):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.system_type = system_type
        self.use_tls = use_tls
        self.tls_config = tls_config
        
        # Стан клієнта
        self.reader = None
        self.writer = None
        self.is_connected = False
        self.is_bound = False
        self.bind_type = None
        
        # Лічильник послідовності
        self.sequence_number = 0
        
        # Транспорт TLS
        self.transport = None
        if use_tls:
            self.transport = SecureTransport(tls_config, server_mode=False)
        
        # Парсер PDU
        self.pdu_parser = pdu_parser or PDUParser()
        
        # Ідентифікатор клієнта
        self.client_id = f"smpp_client_{random.randint(10000, 99999)}"
        
        # Callback-и для відповідей
        self.response_handlers = {}
        
        logger.info(
            f"SMPP клієнт створено {self.client_id}",
            {
                "host": host,
                "port": port,
                "system_id": system_id,
                "use_tls": use_tls
            }
        )
    
    async def connect(self) -> bool:
        """
        Встановлює з'єднання з SMPP сервером
        """
        try:
            if self.use_tls and self.transport:
                self.reader, self.writer = await self.transport.open_connection(self.host, self.port)
            else:
                self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
                
            self.is_connected = True
            logger.info(f"Клієнт {self.client_id} підключено до {self.host}:{self.port}")
            
            # Запускаємо обробник вхідних повідомлень
            asyncio.create_task(self._read_pdus())
            
            return True
            
        except Exception as e:
            logger.error(f"Помилка підключення до {self.host}:{self.port}: {e}")
            return False
    
    async def disconnect(self) -> None:
        """
        Розриває з'єднання з SMPP сервером
        """
        if self.is_bound:
            await self.unbind()
            
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except:
                pass
                
        self.is_connected = False
        self.is_bound = False
        logger.info(f"Клієнт {self.client_id} відключено")
    
    async def bind_transmitter(self) -> Dict[str, Any]:
        """
        Виконує операцію bind_transmitter
        """
        return await self._bind("bind_transmitter")
    
    async def bind_receiver(self) -> Dict[str, Any]:
        """
        Виконує операцію bind_receiver
        """
        return await self._bind("bind_receiver")
    
    async def bind_transceiver(self) -> Dict[str, Any]:
        """
        Виконує операцію bind_transceiver
        """
        return await self._bind("bind_transceiver")
    
    async def _bind(self, bind_type: str) -> Dict[str, Any]:
        """
        Внутрішня функція для операцій bind
        """
        if not self.is_connected:
            raise ConnectionError("Клієнт не підключено")
            
        if self.is_bound:
            logger.warning(f"Клієнт {self.client_id} вже виконав bind як {self.bind_type}")
            return {"status": "already_bound", "bind_type": self.bind_type}
        
        command_id = {
            "bind_transmitter": 0x00000002,
            "bind_receiver": 0x00000001,
            "bind_transceiver": 0x00000009
        }.get(bind_type)
        
        if not command_id:
            raise ValueError(f"Невідомий тип bind: {bind_type}")
        
        # Формуємо PDU для bind
        sequence_number = self._get_next_sequence()
        
        # Збираємо тіло PDU
        body = b''
        body += self.system_id.encode('utf-8') + b'\x00'  # system_id
        body += self.password.encode('utf-8') + b'\x00'   # password
        body += self.system_type.encode('utf-8') + b'\x00'  # system_type
        body += struct.pack('!BBB', 
            0x34,  # interface_version (SMPP 3.4)
            0x00,  # addr_ton
            0x00   # addr_npi
        )
        body += b'\x00'  # address_range (empty)
        
        # Формуємо заголовок
        header = struct.pack('!IIII',
            16 + len(body),  # command_length
            command_id,      # command_id
            0x00000000,      # command_status
            sequence_number  # sequence_number
        )
        
        # Відправляємо PDU
        bind_pdu = header + body
        future = asyncio.Future()
        resp_command_id = command_id | 0x80000000  # Response ID
        self.response_handlers[sequence_number] = {
            "future": future,
            "command_id": resp_command_id
        }
        
        await self._send_pdu(bind_pdu)
        
        try:
            # Очікуємо відповідь
            response = await asyncio.wait_for(future, timeout=10.0)
            
            if response.get("command_status") == 0:
                self.is_bound = True
                self.bind_type = bind_type
                logger.info(f"Клієнт {self.client_id} успішно виконав {bind_type}")
            else:
                status_name = response.get("status_name", "UNKNOWN")
                logger.error(f"Помилка bind: {status_name}")
                
            return response
        except asyncio.TimeoutError:
            logger.error(f"Таймаут очікування відповіді на {bind_type}")
            del self.response_handlers[sequence_number]
            return {"error": "timeout", "command": bind_type}
    
    async def unbind(self) -> Dict[str, Any]:
        """
        Виконує операцію unbind
        """
        if not self.is_connected or not self.is_bound:
            logger.warning(f"Клієнт {self.client_id} не виконав bind")
            return {"status": "not_bound"}
        
        sequence_number = self._get_next_sequence()
        
        # Формуємо PDU для unbind
        header = struct.pack('!IIII',
            16,               # command_length (тільки заголовок)
            0x00000006,       # command_id (unbind)
            0x00000000,       # command_status
            sequence_number   # sequence_number
        )
        
        # Відправляємо PDU
        unbind_pdu = header
        future = asyncio.Future()
        self.response_handlers[sequence_number] = {
            "future": future,
            "command_id": 0x80000006  # unbind_resp
        }
        
        await self._send_pdu(unbind_pdu)
        
        try:
            # Очікуємо відповідь
            response = await asyncio.wait_for(future, timeout=10.0)
            
            if response.get("command_status") == 0:
                self.is_bound = False
                self.bind_type = None
                logger.info(f"Клієнт {self.client_id} успішно виконав unbind")
            else:
                status_name = response.get("status_name", "UNKNOWN")
                logger.error(f"Помилка unbind: {status_name}")
                
            return response
        except asyncio.TimeoutError:
            logger.error("Таймаут очікування відповіді на unbind")
            del self.response_handlers[sequence_number]
            return {"error": "timeout", "command": "unbind"}
    
    async def enquire_link(self) -> Dict[str, Any]:
        """
        Відправляє enquire_link для перевірки з'єднання
        """
        if not self.is_connected:
            raise ConnectionError("Клієнт не підключено")
        
        sequence_number = self._get_next_sequence()
        
        # Формуємо PDU для enquire_link
        header = struct.pack('!IIII',
            16,               # command_length (тільки заголовок)
            0x00000015,       # command_id (enquire_link)
            0x00000000,       # command_status
            sequence_number   # sequence_number
        )
        
        # Відправляємо PDU
        enquire_pdu = header
        future = asyncio.Future()
        self.response_handlers[sequence_number] = {
            "future": future,
            "command_id": 0x80000015  # enquire_link_resp
        }
        
        await self._send_pdu(enquire_pdu)
        
        try:
            # Очікуємо відповідь
            response = await asyncio.wait_for(future, timeout=5.0)
            return response
        except asyncio.TimeoutError:
            logger.error("Таймаут очікування відповіді на enquire_link")
            del self.response_handlers[sequence_number]
            return {"error": "timeout", "command": "enquire_link"}
    
    async def submit_sm(
        self,
        source_addr: str,
        destination_addr: str,
        short_message: str,
        source_addr_ton: int = 5,
        source_addr_npi: int = 0,
        dest_addr_ton: int = 1,
        dest_addr_npi: int = 1,
        service_type: str = "",
        esm_class: int = 0,
        protocol_id: int = 0,
        priority_flag: int = 0,
        schedule_delivery_time: str = "",
        validity_period: str = "",
        registered_delivery: int = 0,
        replace_if_present_flag: int = 0,
        data_coding: int = 0,
        sm_default_msg_id: int = 0,
        optional_params: Optional[Dict[int, bytes]] = None
    ) -> Dict[str, Any]:
        """
        Відправляє SMS повідомлення (submit_sm)
        """
        if not self.is_connected or not self.is_bound:
            raise ConnectionError("Клієнт не виконав bind або не підключено")
            
        if self.bind_type == "bind_receiver":
            raise ValueError("Клієнт у режимі receiver не може відправляти повідомлення")
        
        sequence_number = self._get_next_sequence()
        
        # Кодуємо короткі повідомлення в UTF-8
        if data_coding == 0 or data_coding == 1:
            short_message_bytes = short_message.encode('utf-8')
        elif data_coding == 8:
            short_message_bytes = short_message.encode('utf-16-be')
        else:
            short_message_bytes = short_message.encode('utf-8')
        
        # Обмеження на довжину повідомлення
        if len(short_message_bytes) > 254:
            logger.warning("Повідомлення занадто довге, буде обрізано до 254 байт")
            short_message_bytes = short_message_bytes[:254]
        
        # Формуємо тіло PDU
        body = b''
        body += service_type.encode('utf-8') + b'\x00'  # service_type
        body += struct.pack('!BB', source_addr_ton, source_addr_npi)  # source_addr_ton, source_addr_npi
        body += source_addr.encode('utf-8') + b'\x00'  # source_addr
        body += struct.pack('!BB', dest_addr_ton, dest_addr_npi)  # dest_addr_ton, dest_addr_npi
        body += destination_addr.encode('utf-8') + b'\x00'  # destination_addr
        body += struct.pack('!BBB', 
            esm_class,  # esm_class
            protocol_id,  # protocol_id
            priority_flag  # priority_flag
        )
        body += schedule_delivery_time.encode('utf-8') + b'\x00'  # schedule_delivery_time
        body += validity_period.encode('utf-8') + b'\x00'  # validity_period
        body += struct.pack('!BBB', 
            registered_delivery,  # registered_delivery
            replace_if_present_flag,  # replace_if_present_flag
            data_coding  # data_coding
        )
        body += struct.pack('!B', sm_default_msg_id)  # sm_default_msg_id
        body += struct.pack('!B', len(short_message_bytes))  # sm_length
        body += short_message_bytes  # short_message
        
        # Додаємо опціональні параметри
        if optional_params:
            for tag, value in optional_params.items():
                body += struct.pack('!HH', tag, len(value))
                body += value
        
        # Формуємо заголовок
        header = struct.pack('!IIII',
            16 + len(body),  # command_length
            0x00000004,      # command_id (submit_sm)
            0x00000000,      # command_status
            sequence_number  # sequence_number
        )
        
        # Відправляємо PDU
        submit_pdu = header + body
        future = asyncio.Future()
        self.response_handlers[sequence_number] = {
            "future": future,
            "command_id": 0x80000004  # submit_sm_resp
        }
        
        await self._send_pdu(submit_pdu)
        
        try:
            # Очікуємо відповідь
            response = await asyncio.wait_for(future, timeout=10.0)
            
            if response.get("command_status") == 0:
                logger.info(f"Повідомлення успішно відправлено на {destination_addr}")
            else:
                status_name = response.get("status_name", "UNKNOWN")
                logger.error(f"Помилка відправлення повідомлення: {status_name}")
                
            return response
        except asyncio.TimeoutError:
            logger.error("Таймаут очікування відповіді на submit_sm")
            del self.response_handlers[sequence_number]
            return {"error": "timeout", "command": "submit_sm"}
    
    async def _send_pdu(self, pdu_data: bytes) -> None:
        """
        Відправляє PDU через з'єднання
        """
        if not self.writer:
            raise ConnectionError("Клієнт не підключено")
            
        try:
            self.writer.write(pdu_data)
            await self.writer.drain()
            logger.debug(f"PDU відправлено: {binascii.hexlify(pdu_data[:16]).decode()}")
        except Exception as e:
            logger.error(f"Помилка відправлення PDU: {e}")
            raise
    
    async def _read_pdus(self) -> None:
        """
        Обробник вхідних PDU
        """
        try:
            while self.is_connected and self.reader:
                # Читаємо заголовок (4 байта для command_length)
                header_data = await self.reader.readexactly(4)
                command_length = struct.unpack('!I', header_data)[0]
                
                # Читаємо решту PDU
                remaining_data = await self.reader.readexactly(command_length - 4)
                pdu_data = header_data + remaining_data
                
                # Парсимо PDU
                parsed_pdu = self.pdu_parser.parse_pdu(pdu_data)
                sequence_number = parsed_pdu.get("sequence_number")
                command_id = parsed_pdu.get("command_id")
                
                # Вхідні команди (не відповіді)
                if command_id == 0x00000005:  # deliver_sm
                    # Автоматично відповідаємо на deliver_sm
                    await self._handle_deliver_sm(parsed_pdu, pdu_data)
                elif command_id == 0x00000015:  # enquire_link
                    # Автоматично відповідаємо на enquire_link
                    await self._handle_enquire_link(parsed_pdu)
                elif sequence_number in self.response_handlers:
                    # Обробляємо відповіді
                    handler = self.response_handlers[sequence_number]
                    if handler["command_id"] == command_id:
                        future = handler["future"]
                        if not future.done():
                            future.set_result(parsed_pdu)
                        del self.response_handlers[sequence_number]
                    else:
                        logger.warning(
                            f"Отримано unexpected PDU: {parsed_pdu.get('command_name')}, "
                            f"очікувався: {hex(handler['command_id'])}"
                        )
                else:
                    logger.info(f"Отримано PDU: {parsed_pdu.get('command_name')}")
                
        except (asyncio.IncompleteReadError, ConnectionError) as e:
            logger.warning(f"З'єднання закрито: {e}")
            self.is_connected = False
            self.is_bound = False
        except Exception as e:
            logger.error(f"Помилка читання PDU: {e}")
            self.is_connected = False
            self.is_bound = False
    
    async def _handle_deliver_sm(self, parsed_pdu: Dict[str, Any], raw_pdu: bytes) -> None:
        """
        Обробляє deliver_sm та надсилає відповідь
        """
        sequence_number = parsed_pdu.get("sequence_number")
        
        # Формуємо відповідь
        response = struct.pack('!IIII',
            16,               # command_length (тільки заголовок)
            0x80000005,       # command_id (deliver_sm_resp)
            0x00000000,       # command_status (OK)
            sequence_number   # sequence_number
        )
        
        await self._send_pdu(response)
        logger.info(f"Відправлено deliver_sm_resp для seq: {sequence_number}")
    
    async def _handle_enquire_link(self, parsed_pdu: Dict[str, Any]) -> None:
        """
        Обробляє enquire_link та надсилає відповідь
        """
        sequence_number = parsed_pdu.get("sequence_number")
        
        # Формуємо відповідь
        response = struct.pack('!IIII',
            16,               # command_length (тільки заголовок)
            0x80000015,       # command_id (enquire_link_resp)
            0x00000000,       # command_status (OK)
            sequence_number   # sequence_number
        )
        
        await self._send_pdu(response)
        logger.debug(f"Відправлено enquire_link_resp для seq: {sequence_number}")
    
    def _get_next_sequence(self) -> int:
        """
        Генерує наступний номер послідовності
        """
        self.sequence_number = (self.sequence_number + 1) % 0x7FFFFFFF
        if self.sequence_number == 0:
            self.sequence_number = 1
        return self.sequence_number
