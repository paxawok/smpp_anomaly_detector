# 💬 smpp\_anomaly\_detector

> 🎯 **Розумна система безпеки SMPP у режимі реального часу**

🛰️ *Інтегрована система виявлення аномалій у SMPP-протоколі з TLS-захистом, базовим машинним навчанням, контентним аналізом та CLI-моніторингом.*

---

## 🚀 Почати швидко

```bash
git clone https://github.com/your_username/smpp_anomaly_detector.git
cd smpp_anomaly_detector
poetry install
```

Запусти симуляцію трафіку:

```bash
poetry run python -m cli.simulator --type mixed
```

Моніторинг у реальному часі:

```bash
poetry run python -m cli.terminal_ui monitor
```

---

## 🧠 Що вміє система

| Модуль                 | Опис                                                                    |
| ---------------------- | ----------------------------------------------------------------------- |
| 📡 `smpp_proxy/`       | Проксі між клієнтом і SMSC, з TLS та перехопленням `submit_sm`          |
| 🧠 `anomaly_detector/` | Поведінковий, сигнатурний та контентний аналіз повідомлень              |
| 🧮 `decision_engine/`  | Обчислення ризику та прийняття рішення `allow` / `block` / `suspicious` |
| 🔐 `crypto/`           | TLS-конфігурація, шифрування, вибір cipher suites                       |
| 🧪 `ml_models/`        | Isolation Forest (експериментальне виявлення відхилень)                 |
| 💾 `storage/`          | SQLite: зберігання лічильників, сесій, історії                          |
| 🧪 `tests/`            | Pytest-юніти для ключових компонентів                                   |
| 🖥️ `cli/`             | Кольоровий термінальний інтерфейс для моніторингу й генерації трафіку   |

---

## ⚔️ Типи виявлюваних загроз

* 🔗 **Фішинг** — шкідливі посилання, фейкові SMS від банків
* 🤖 **Flood / DoS** — масові `submit_sm` від одного джерела
* 🧩 **Обфускація ключових слів** — `саsln0`, `m0n0bank`, `$ms`
* 📍 **Спуфінг номера відправника** — підміна `source_addr`
* 🚫 **Заборонені напрямки** — номери з окупованих територій

---

## 🧩 Архітектура

```
   SMPP-клієнт
       ↓
  [ smpp_proxy ] ↔ (TLS) ↔ SMSC
       ↓
 [ anomaly_detector ]
   ↙       ↓         ↘
content  behavior  signature
       ↓
 [ decision_engine ] → verdict.json
       ↓
  Allow / Block / Suspicious
```

---

## 📈 Метрики / логування

| Поле         | Значення прикладу |
| ------------ | ----------------- |
| `source`     | MyBank            |
| `dest`       | 380XXXXXXXXX      |
| `risk_score` | 0.81              |
| `decision`   | blocked           |
| `tags`       | phishing, spoof   |

Логи у форматі JSON: `logs/smpp_log.jsonl`.

---

## 🧪 Тестування

```bash
poetry run pytest
python test_sqlite_integration.py
```

---

## 🛠 Залежності

* **Python 3.10+**
* **Poetry** — менеджер залежностей
* **SQLite** — локальне сховище (замість Redis)
* **smpplib** — обробка SMPP
* **python-Levenshtein** — для виявлення обфускацій
* **colorama** — кольоровий термінал

---

## 🔮 Розширення

* 🌐 Web UI (на Flask або React)
* 🧠 Розширене ML (PCA, Autoencoder, RNN)
* 🔗 SIEM-інтеграція (Splunk, ELK, Graylog)
* 🛡 Постквантові cipher-и (Kyber, NTRU)

---

## 👤 Авторство

Розроблено в рамках дипломної роботи бакалавра
**КНУ імені Тараса Шевченка, Факультет інформаційних технологій**
Виконавець: **Черевач Юрій Анатолійович**
Керівник: **Ставицький Сергій Дмитрович**
2025
Ліцензія: MIT
