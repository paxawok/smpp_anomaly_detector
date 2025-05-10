from typing import Dict, Any, Optional, Union, Tuple
import struct
import binascii
import re
from logging.logger import SMPPLogger

logger = SMPPLogger("pdu_parser")

# Константи SMPP
COMMAND_IDS = {
    0x00000001: "bind_receiver",
    0x80000001: "bind_receiver_resp",
    0x00000002: "bind_transmitter",
    0x80000002: "bind_transmitter_resp",
    0x00000003: "query_sm",
    0x80000003: "query_sm_resp",
    0x00000004: "submit_sm",
    0x80000004: "submit_sm_resp",
    0x00000005: "deliver_sm",
    0x80000005: "deliver_sm_resp",
    0x00000006: "unbind",
    0x80000006: "unbind_resp",
    0x00000007: "replace_sm",
    0x80000007: "replace_sm_resp",
    0x00000008: "cancel_sm",
    0x80000008: "cancel_sm_resp",
    0x00000009: "bind_transceiver",
    0x80000009: "bind_transceiver_resp",
    0x0000000B: "outbind",
    0x00000015: "enquire_link",
    0x80000015: "enquire_link_resp",
    0x00000021: "submit_multi",
    0x80000021: "submit_multi_resp",
    0x00000102: "alert_notification",
    0x00000103: "data_sm",
    0x80000103: "data_sm_resp",
}

COMMAND_STATUS = {
    0x00000000: "ESME_ROK",
    0x00000001: "ESME_RINVMSGLEN",
    0x00000002: "ESME_RINVCMDLEN",
    0x00000003: "ESME_RINVCMDID",
    0x00000004: "ESME_RINVBNDSTS",
    0x00000005: "ESME_RALYBND",
    0x00000006: "ESME_RINVPRTFLG",
    0x00000007: "ESME_RINVREGDLVFLG",
    0x00000008: "ESME_RSYSERR",
    # Додаткові статуси можна додати за потреби
}

class PDUParser:
    """
    Клас для парсингу PDU-повідомлень SMPP-протоколу
    """
    def __init__(self):
        self.header_format = ">IIII"  # command_length, command_id, command_status, sequence_number
        self.header_length = struct.calcsize(self.header_format)
    
    def parse_header(self, data: bytes) -> Dict[str, Any]:
        """
        Розбирає заголовок PDU
        """
        if len(data) < self.header_length:
            raise ValueError(f"Недостатньо даних для заголовка: {len(data)} < {self.header_length}")
        
        command_length, command_id, command_status, sequence_number = struct.unpack(
            self.header_format, data[:self.header_length]
        )
        
        command_name = COMMAND_IDS.get(command_id, f"UNKNOWN_COMMAND_{command_id}")
        status_name = COMMAND_STATUS.get(command_status, f"UNKNOWN_STATUS_{command_status}")
        
        return {
            "command_length": command_length,
            "command_id": command_id,
            "command_name": command_name,
            "command_status": command_status,
            "status_name": status_name,
            "sequence_number": sequence_number
        }
    
    def parse_c_string(self, data: bytes, offset: int) -> Tuple[str, int]:
        """
        Розбирає C-string (null-terminated string) з даних, починаючи з offset
        Повертає (рядок, новий_offset)
        """
        null_pos = data.find(b'\x00', offset)
        if null_pos == -1:
            raise ValueError(f"C-string не має термінуючого нуля: {data[offset:]}")
            
        s = data[offset:null_pos].decode('utf-8', errors='replace')
        return s, null_pos + 1
    
    def parse_submit_sm(self, data: bytes) -> Dict[str, Any]:
        """
        Розбирає PDU для submit_sm
        """
        try:
            header = self.parse_header(data)
            if header["command_name"] != "submit_sm":
                logger.warning(f"Очікувався submit_sm, отримано {header['command_name']}")
                return header
            
            result = header.copy()
            offset = self.header_length
            
            # service_type
            service_type, offset = self.parse_c_string(data, offset)
            result["service_type"] = service_type
            
            # source_addr_ton
            result["source_addr_ton"] = data[offset]
            offset += 1
            
            # source_addr_npi
            result["source_addr_npi"] = data[offset]
            offset += 1
            
            # source_addr
            source_addr, offset = self.parse_c_string(data, offset)
            result["source_addr"] = source_addr
            
            # dest_addr_ton
            result["dest_addr_ton"] = data[offset]
            offset += 1
            
            # dest_addr_npi
            result["dest_addr_npi"] = data[offset]
            offset += 1
            
            # destination_addr
            destination_addr, offset = self.parse_c_string(data, offset)
            result["destination_addr"] = destination_addr
            
            # esm_class
            result["esm_class"] = data[offset]
            offset += 1
            
            # protocol_id
            result["protocol_id"] = data[offset]
            offset += 1
            
            # priority_flag
            result["priority_flag"] = data[offset]
            offset += 1
            
            # schedule_delivery_time
            schedule_delivery_time, offset = self.parse_c_string(data, offset)
            result["schedule_delivery_time"] = schedule_delivery_time
            
            # validity_period
            validity_period, offset = self.parse_c_string(data, offset)
            result["validity_period"] = validity_period
            
            # registered_delivery
            result["registered_delivery"] = data[offset]
            offset += 1
            
            # replace_if_present_flag
            result["replace_if_present_flag"] = data[offset]
            offset += 1
            
            # data_coding
            result["data_coding"] = data[offset]
            offset += 1
            
            # sm_default_msg_id
            result["sm_default_msg_id"] = data[offset]
            offset += 1
            
            # sm_length
            sm_length = data[offset]
            result["sm_length"] = sm_length
            offset += 1
            
            # short_message
            short_message = data[offset:offset+sm_length]
            
            # Спробуємо декодувати повідомлення відповідно до data_coding
            try:
                if result["data_coding"] == 0:  # Default GSM alphabet
                    result["short_message"] = short_message.decode('utf-8', errors='replace')
                elif result["data_coding"] == 8:  # UCS2 / UTF-16
                    result["short_message"] = short_message.decode('utf-16-be', errors='replace')
                else:
                    result["short_message"] = short_message.decode('utf-8', errors='replace')
            except Exception as e:
                logger.error(f"Помилка декодування повідомлення: {e}")
                result["short_message"] = binascii.hexlify(short_message).decode('ascii')
                
            result["short_message_hex"] = binascii.hexlify(short_message).decode('ascii')
            offset += sm_length
            
            # Optional parameters
            result["optional_params"] = {}
            
            while offset < header["command_length"]:
                if offset + 4 > len(data):
                    break
                    
                tag = struct.unpack(">H", data[offset:offset+2])[0]
                offset += 2
                
                length = struct.unpack(">H", data[offset:offset+2])[0]
                offset += 2
                
                if offset + length > len(data):
                    break
                    
                value = data[offset:offset+length]
                result["optional_params"][tag] = binascii.hexlify(value).decode('ascii')
                offset += length
            
            return result
            
        except Exception as e:
            logger.error(f"Помилка парсингу submit_sm: {e}")
            return {"error": str(e)}
    
    def parse_pdu(self, data: bytes) -> Dict[str, Any]:
        """
        Загальна функція для парсингу PDU
        """
        try:
            header = self.parse_header(data)
            
            # Вибираємо специфічний парсер залежно від типу команди
            if header["command_name"] == "submit_sm":
                return self.parse_submit_sm(data)
            else:
                return header
                
        except Exception as e:
            logger.error(f"Помилка парсингу PDU: {e}")
            return {"error": str(e)}
    
    def extract_urls(self, message: str) -> list:
        """
        Витягує URL з повідомлення
        """
        # Простий регулярний вираз для виявлення URL
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|bit\.ly/[^\s<>"\']+|t\.me/[^\s<>"\']+'
        return re.findall(url_pattern, message)
    
    def extract_phone_numbers(self, message: str) -> list:
        """
        Витягує номери телефонів з повідомлення
        """
        # Регулярний вираз для виявлення українських номерів
        phone_pattern = r'\+?38[- ]?0\d{2}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}|\+?380\d{9}'
        return re.findall(phone_pattern, message)