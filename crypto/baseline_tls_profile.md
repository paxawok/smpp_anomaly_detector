# Базовий профіль TLS для SMPP Anomaly Detector

## Загальні налаштування

- **Мінімальна версія TLS**: 1.2
- **Рекомендована версія TLS**: 1.3
- **Перевірка сертифікатів**: Увімкнено
- **Режим верифікації**: CERT_REQUIRED (у виробництві)

## Рекомендовані Cipher Suites

### TLS 1.3
- TLS_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_CHACHA20_POLY1305_SHA256

### TLS 1.2
- ECDHE-ECDSA-AES256-GCM-SHA384
- ECDHE-RSA-AES256-GCM-SHA384
- ECDHE-ECDSA-CHACHA20-POLY1305
- ECDHE-RSA-CHACHA20-POLY1305
- ECDHE-ECDSA-AES128-GCM-SHA256
- ECDHE-RSA-AES128-GCM-SHA256
- ECDHE-ECDSA-AES256-SHA384
- ECDHE-RSA-AES256-SHA384
- ECDHE-ECDSA-AES128-SHA256
- ECDHE-RSA-AES128-SHA256

## Параметри OpenSSL

- OP_NO_SSLv2
- OP_NO_SSLv3
- OP_NO_TLSv1
- OP_NO_TLSv1_1
- OP_NO_COMPRESSION
- OP_CIPHER_SERVER_PREFERENCE
- OP_SINGLE_DH_USE
- OP_SINGLE_ECDH_USE

## Сертифікати

- **Розмір ключа RSA**: Не менше 2048 біт
- **Криві ECC**: secp256r1, secp384r1, secp521r1
- **Термін дії**: Не більше 398 днів
- **Алгоритм підпису**: SHA-256 або сильніше

## Рекомендації для середовищ розробки

Для середовищ розробки можна використовувати самопідписані сертифікати, створені за допомогою команд:

```bash
# Створення приватного ключа
openssl genrsa -out server.key 2048

# Створення самопідписаного сертифіката
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/C=UA/ST=Kyiv/L=Kyiv/O=SMPP Anomaly Detector/CN=localhost"
```

## Рекомендації для виробництва

- Використовувати сертифікати від довірених CA
- Регулярно оновлювати сертифікати (щонайменше 1 раз на рік)
- Налаштувати OCSP Stapling
- Впровадити Certificate Transparency
- Використовувати Certificate Pinning для критичних компонентів
- Розглянути можливість використання взаємної TLS автентифікації (mTLS)

## Постквантова криптографія

У майбутніх версіях планується впровадження підтримки постквантових алгоритмів, зокрема:

- Kyber (NIST стандарт для шифрування)
- Dilithium (NIST стандарт для підписів)
- NTRU
- SPHINCS+

## Моніторинг та аудит

- Логування всіх помилок TLS
- Регулярна перевірка налаштувань за допомогою інструментів типу SSL Labs
- Моніторинг вразливостей в компонентах TLS
- Дотримання найкращих практик OWASP для TLS