"""
Модуль для перевірки географічних обмежень телекомунікаційних параметрів.
Фокусується на перевірці MCC/MNC кодів та префіксів телефонних номерів
з окупованих територій.
"""


def is_restricted_mcc_mnc(mcc: str, mnc: str) -> bool:
    """
    Перевіряє, чи входить пара MCC/MNC до списку заблокованих.
    
    Args:
        mcc: Код країни мобільного зв'язку (3 цифри)
        mnc: Код мобільної мережі (2-3 цифри)
        
    Returns:
        bool: True, якщо пара MCC/MNC заблокована, інакше False
    """
    # Список заблокованих MCC/MNC комбінацій
    restricted_pairs = [
        ("250", "32"),  # К-Телеком
        ("250", "54"),  # Миранда-Медиа
        ("250", "97")   # Феникс
    ]
    
    # Нормалізуємо коди (видаляємо пробіли, забезпечуємо рядковий тип)
    mcc = str(mcc).strip()
    mnc = str(mnc).strip()
    
    # Перевіряємо наявність пари в списку заблокованих MCC/MNC
    return (mcc, mnc) in restricted_pairs


def is_restricted_prefix(phone_number: str) -> bool:
    """
    Перевіряє, чи починається номер телефону з одного із заблокованих префіксів.
    
    Args:
        phone_number: Номер телефону (напр. +79781234567)
        
    Returns:
        bool: True, якщо номер починається з забл. префіксу, інакше False
    """
    # Список заблокованих префіксів
    restricted_prefixes = [
        "+7978",  # АРК
        "+7949"   # ОРДЛО
    ]
    
    normalized_number = ''.join(c for c in phone_number if c.isdigit() or c == '+')
    
    # Перевіряємо кожен префікс
    for prefix in restricted_prefixes:
        if normalized_number.startswith(prefix):
            return True
            
    return False


# Приклад використання
if __name__ == "__main__":
    # Тестування перевірки MCC/MNC
    mcc_mnc_tests = [
        ("250", "32"),  # К-Телеком - заблокований
        ("250", "54"),  # Миранда-Медиа - заблокований
        ("250", "97"),  # Феникс - заблокований
        ("255", "32"),  # Не заблокований
        ("250", "01")   # Не заблокований
    ]
    
    print("=== Тестування перевірки MCC/MNC ===")
    for mcc, mnc in mcc_mnc_tests:
        result = is_restricted_mcc_mnc(mcc, mnc)
        status = "ЗАБЛОКОВАНО" if result else "Дозволено"
        print(f"MCC/MNC: {mcc}/{mnc} - {status}")
    
    print("\n=== Тестування перевірки префіксів номерів ===")
    phone_tests = [
        "+7978123456",   # Заблокований (Крим)
        "+79491234567",  # Заблокований (Севастополь)
        "+380501234567", # Дозволений (Україна)
        "+7495123456",   # Дозволений (Росія, але не в списку)
        "0501234567"     # Дозволений (Україна)
    ]
    
    for phone in phone_tests:
        result = is_restricted_prefix(phone)
        status = "ЗАБЛОКОВАНО" if result else "Дозволено"
        print(f"Номер: {phone} - {status}")