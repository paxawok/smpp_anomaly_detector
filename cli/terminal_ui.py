#!/usr/bin/env python
import asyncio
import argparse
import os
import sys
import json
import time
import curses
import textwrap
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime

# Додаємо батьківський каталог до шляху для імпорту
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Імпортуємо компоненти системи
from logger.logger import SMPPLogger
from storage.redis_client import RedisClient

# Налаштування для colorama для Windows
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    # Заглушки для colorama
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = Back = Style = DummyColor()

logger = SMPPLogger("terminal_ui")

class TerminalMonitor:
    """
    Клас для моніторингу та відображення роботи SMPP системи в консолі
    """
    def __init__(self, logs_dir: str = "logs", refresh_interval: float = 1.0):
        self.logs_dir = logs_dir
        self.refresh_interval = refresh_interval
        self.running = False
        self.redis = RedisClient()
        self.log_file = os.path.join(logs_dir, "smpp_log.jsonl")
        
        # Останній прочитаний рядок логу
        self.last_log_position = 0
        
        # Статистика
        self.stats = {
            "total_messages": 0,
            "blocked_messages": 0,
            "suspicious_messages": 0,
            "allowed_messages": 0,
            "start_time": time.time(),
            "top_sources": {},
            "top_destinations": {},
            "top_tags": {}
        }
        
        # Буфер для відображення останніх повідомлень
        self.recent_logs = []
        self.max_recent_logs = 20
        
        logger.info("TerminalMonitor ініціалізовано")
    
    async def connect(self) -> None:
        """
        Підключається до Redis
        """
        await self.redis.connect()
    
    async def disconnect(self) -> None:
        """
        Відключається від Redis
        """
        await self.redis.disconnect()
    
    def read_new_logs(self) -> List[Dict[str, Any]]:
        """
        Читає нові записи з лог-файлу
        """
        new_logs = []
        
        try:
            if not os.path.exists(self.log_file):
                return new_logs
                
            with open(self.log_file, "r", encoding="utf-8") as f:
                # Перемотуємо до останньої прочитаної позиції
                f.seek(self.last_log_position)
                
                # Читаємо нові рядки
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        new_logs.append(log_entry)
                    except json.JSONDecodeError:
                        pass
                
                # Оновлюємо позицію
                self.last_log_position = f.tell()
                
            return new_logs
            
        except Exception as e:
            logger.error(f"Помилка читання логів: {e}")
            return new_logs
    
    def update_stats(self, new_logs: List[Dict[str, Any]]) -> None:
        """
        Оновлює статистику на основі нових логів
        """
        # Аналізуємо нові записи
        for log in new_logs:
            # Перевіряємо, чи це запис про аномалію
            if log.get("level") == "ANOMALY":
                self.stats["total_messages"] += 1
                
                decision = log.get("decision", "allowed").lower()
                if decision == "blocked":
                    self.stats["blocked_messages"] += 1
                elif decision == "suspicious":
                    self.stats["suspicious_messages"] += 1
                else:
                    self.stats["allowed_messages"] += 1
                
                # Оновлюємо статистику по джерелах
                source = log.get("source")
                if source:
                    self.stats["top_sources"][source] = self.stats["top_sources"].get(source, 0) + 1
                
                # Оновлюємо статистику по одержувачах
                dest = log.get("dest")
                if dest:
                    self.stats["top_destinations"][dest] = self.stats["top_destinations"].get(dest, 0) + 1
                
                # Оновлюємо статистику по тегах
                tags = log.get("tags", [])
                for tag in tags:
                    self.stats["top_tags"][tag] = self.stats["top_tags"].get(tag, 0) + 1
                
                # Додаємо до останніх логів
                self.recent_logs.append(log)
                # Обмежуємо розмір буфера
                if len(self.recent_logs) > self.max_recent_logs:
                    self.recent_logs = self.recent_logs[-self.max_recent_logs:]
    
    async def get_redis_stats(self) -> Dict[str, Any]:
        """
        Отримує статистику з Redis
        """
        result = {}
        
        try:
            # Отримуємо інформацію про rate-limiting
            # Тут можна додати інші запити до Redis для отримання додаткової статистики
            
            return result
            
        except Exception as e:
            logger.error(f"Помилка отримання статистики з Redis: {e}")
            return result
    
    def render_text_dashboard(self) -> str:
        """
        Формує текстовий дашборд для відображення в консолі
        """
        # Заголовок
        dashboard = f"""
{Fore.CYAN}{'='*80}
{Fore.WHITE}{Back.BLUE} SMPP ANOMALY DETECTOR - СТАТИСТИКА МОНІТОРИНГУ {Style.RESET_ALL}
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
"""
        
        # Основна статистика
        uptime = time.time() - self.stats["start_time"]
        uptime_str = f"{int(uptime // 3600):02d}:{int((uptime % 3600) // 60):02d}:{int(uptime % 60):02d}"
        
        dashboard += f"""
{Fore.YELLOW}Загальна статистика:{Style.RESET_ALL}
  • Час роботи: {uptime_str}
  • Всього повідомлень: {self.stats["total_messages"]}
  • Заблоковано: {Fore.RED}{self.stats["blocked_messages"]}{Style.RESET_ALL}
  • Підозрілих: {Fore.YELLOW}{self.stats["suspicious_messages"]}{Style.RESET_ALL}
  • Дозволено: {Fore.GREEN}{self.stats["allowed_messages"]}{Style.RESET_ALL}
"""
        
        # Top 5 джерел
        dashboard += f"\n{Fore.YELLOW}Топ 5 джерел:{Style.RESET_ALL}\n"
        top_sources = sorted(self.stats["top_sources"].items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (source, count) in enumerate(top_sources, 1):
            dashboard += f"  {i}. {source}: {count}\n"
        
        # Top 5 напрямків
        dashboard += f"\n{Fore.YELLOW}Топ 5 напрямків:{Style.RESET_ALL}\n"
        top_dests = sorted(self.stats["top_destinations"].items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (dest, count) in enumerate(top_dests, 1):
            dashboard += f"  {i}. {dest}: {count}\n"
        
        # Top 5 тегів
        dashboard += f"\n{Fore.YELLOW}Топ 5 тегів:{Style.RESET_ALL}\n"
        top_tags = sorted(self.stats["top_tags"].items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (tag, count) in enumerate(top_tags, 1):
            dashboard += f"  {i}. {tag}: {count}\n"
        
        # Останні виявлені аномалії
        dashboard += f"\n{Fore.YELLOW}Останні виявлені аномалії:{Style.RESET_ALL}\n"
        
        if not self.recent_logs:
            dashboard += "  Ще немає записів\n"
        else:
            for i, log in enumerate(reversed(self.recent_logs[-10:]), 1):
                timestamp = log.get("timestamp", "")
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        timestamp = dt.strftime("%H:%M:%S")
                    except:
                        pass
                
                decision = log.get("decision", "").lower()
                if decision == "blocked":
                    decision_colored = f"{Fore.RED}BLOCKED{Style.RESET_ALL}"
                elif decision == "suspicious":
                    decision_colored = f"{Fore.YELLOW}SUSPICIOUS{Style.RESET_ALL}"
                else:
                    decision_colored = f"{Fore.GREEN}ALLOWED{Style.RESET_ALL}"
                
                source = log.get("source", "")
                dest = log.get("dest", "")
                risk = log.get("risk_score", 0)
                tags = ", ".join(log.get("tags", []))
                
                dashboard += f"  {i}. [{timestamp}] {source} -> {dest} | {decision_colored} | Risk: {risk:.2f} | Tags: {tags}\n"
        
        # Підказки
        dashboard += f"""
{Fore.CYAN}{'='*80}
{Fore.WHITE} Ctrl+C - Вихід | R - Скинути статистику
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
"""
        
        return dashboard
    
    async def run_text_mode(self) -> None:
        """
        Запускає моніторинг в текстовому режимі (без curses)
        """
        self.running = True
        
        try:
            while self.running:
                # Читаємо нові логи
                new_logs = self.read_new_logs()
                
                # Оновлюємо статистику
                self.update_stats(new_logs)
                
                # Відображаємо дашборд
                os.system('cls' if os.name == 'nt' else 'clear')
                print(self.render_text_dashboard())
                
                # Пауза перед наступним оновленням
                await asyncio.sleep(self.refresh_interval)
                
        except KeyboardInterrupt:
            self.running = False
            print("\nМоніторинг зупинено користувачем")
        except Exception as e:
            self.running = False
            print(f"Помилка: {e}")
    
    def reset_stats(self) -> None:
        """
        Скидає статистику
        """
        self.stats = {
            "total_messages": 0,
            "blocked_messages": 0,
            "suspicious_messages": 0,
            "allowed_messages": 0,
            "start_time": time.time(),
            "top_sources": {},
            "top_destinations": {},
            "top_tags": {}
        }
        self.recent_logs = []
        logger.info("Статистику скинуто")
    
    async def run_curses_mode(self, stdscr) -> None:
        """
        Запускає моніторинг в режимі curses
        """
        # Налаштування curses
        curses.curs_set(0)  # Ховаємо курсор
        curses.start_color()
        curses.use_default_colors()
        
        # Визначаємо кольорові пари
        curses.init_pair(1, curses.COLOR_GREEN, -1)    # Зелений
        curses.init_pair(2, curses.COLOR_YELLOW, -1)   # Жовтий
        curses.init_pair(3, curses.COLOR_RED, -1)      # Червоний
        curses.init_pair(4, curses.COLOR_CYAN, -1)     # Блакитний
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Білий на синьому
        
        # Встановлюємо таймаут для getch()
        stdscr.timeout(int(self.refresh_interval * 1000))
        
        self.running = True
        
        try:
            while self.running:
                # Отримуємо розміри термінала
                height, width = stdscr.getmaxyx()
                
                # Читаємо нові логи
                new_logs = self.read_new_logs()
                
                # Оновлюємо статистику
                self.update_stats(new_logs)
                
                # Очищаємо екран
                stdscr.clear()
                
                # Рендеримо дашборд
                self._render_curses_dashboard(stdscr, height, width)
                
                # Оновлюємо екран
                stdscr.refresh()
                
                # Перевіряємо клавіатурний ввід
                key = stdscr.getch()
                if key == ord('q') or key == ord('Q') or key == 27:  # q, Q або Esc
                    self.running = False
                elif key == ord('r') or key == ord('R'):  # r, R
                    self.reset_stats()
                
        except KeyboardInterrupt:
            self.running = False
        except Exception as e:
            self.running = False
            logger.error(f"Помилка в curses режимі: {e}")
    
    def _render_curses_dashboard(self, stdscr, height: int, width: int) -> None:
        """
        Рендерить дашборд з використанням curses
        """
        current_row = 0
        
        # Заголовок
        if current_row < height:
            header = " SMPP ANOMALY DETECTOR - СТАТИСТИКА МОНІТОРИНГУ "
            header_pos = max(0, (width - len(header)) // 2)
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(current_row, 0, " " * width)
            stdscr.addstr(current_row, header_pos, header)
            stdscr.attroff(curses.color_pair(5))
            current_row += 1
        
        # Роздільник
        if current_row < height:
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(current_row, 0, "=" * width)
            stdscr.attroff(curses.color_pair(4))
            current_row += 1
        
        # Порожній рядок
        current_row += 1
        
        # Основна статистика
        if current_row < height:
            uptime = time.time() - self.stats["start_time"]
            uptime_str = f"{int(uptime // 3600):02d}:{int((uptime % 3600) // 60):02d}:{int(uptime % 60):02d}"
            
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(current_row, 2, "Загальна статистика:")
            stdscr.attroff(curses.color_pair(2))
            current_row += 1
            
            if current_row < height:
                stdscr.addstr(current_row, 4, f"• Час роботи: {uptime_str}")
                current_row += 1
            
            if current_row < height:
                stdscr.addstr(current_row, 4, f"• Всього повідомлень: {self.stats['total_messages']}")
                current_row += 1
            
            if current_row < height:
                stdscr.addstr(current_row, 4, "• Заблоковано: ")
                stdscr.attron(curses.color_pair(3))
                stdscr.addstr(f"{self.stats['blocked_messages']}")
                stdscr.attroff(curses.color_pair(3))
                current_row += 1
            
            if current_row < height:
                stdscr.addstr(current_row, 4, "• Підозрілих: ")
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(f"{self.stats['suspicious_messages']}")
                stdscr.attroff(curses.color_pair(2))
                current_row += 1
            
            if current_row < height:
                stdscr.addstr(current_row, 4, "• Дозволено: ")
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(f"{self.stats['allowed_messages']}")
                stdscr.attroff(curses.color_pair(1))
                current_row += 1
        
        # Порожній рядок
        current_row += 1
        
        # Розбиваємо екран на колонки
        col_width = width // 3
        
        # Топ 5 джерел
        if current_row < height:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(current_row, 2, "Топ 5 джерел:")
            stdscr.attroff(curses.color_pair(2))
            current_row += 1
            
            top_sources = sorted(self.stats["top_sources"].items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (source, count) in enumerate(top_sources, 1):
                if current_row < height:
                    stdscr.addstr(current_row, 4, f"{i}. {source}: {count}")
                    current_row += 1
        
        # Порожній рядок перед топ напрямками
        current_row += 1
        
        # Топ 5 напрямків
        if current_row < height:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(current_row, 2, "Топ 5 напрямків:")
            stdscr.attroff(curses.color_pair(2))
            current_row += 1
            
            top_dests = sorted(self.stats["top_destinations"].items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (dest, count) in enumerate(top_dests, 1):
                if current_row < height:
                    stdscr.addstr(current_row, 4, f"{i}. {dest}: {count}")
                    current_row += 1
        
        # Скидаємо позицію рядка для наступної колонки
        current_row = 6  # Після заголовка та статистики
        
        # Топ 5 тегів (друга колонка)
        if current_row < height:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(current_row, col_width + 2, "Топ 5 тегів:")
            stdscr.attroff(curses.color_pair(2))
            current_row += 1
            
            top_tags = sorted(self.stats["top_tags"].items(), key=lambda x: x[1], reverse=True)[:5]
            for i, (tag, count) in enumerate(top_tags, 1):
                if current_row < height:
                    stdscr.addstr(current_row, col_width + 4, f"{i}. {tag}: {count}")
                    current_row += 1
        
        # Останні аномалії (внизу екрана)
        log_start_row = max(current_row + 2, height - 15)  # Залишаємо місце для логів та підказок
        
        if log_start_row < height:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(log_start_row, 2, "Останні виявлені аномалії:")
            stdscr.attroff(curses.color_pair(2))
            log_start_row += 1
            
            if not self.recent_logs:
                if log_start_row < height:
                    stdscr.addstr(log_start_row, 4, "Ще немає записів")
            else:
                for i, log in enumerate(reversed(self.recent_logs[-10:]), 1):
                    if log_start_row + i >= height:
                        break
                        
                    timestamp = log.get("timestamp", "")
                    if timestamp:
                        try:
                            dt = datetime.fromisoformat(timestamp)
                            timestamp = dt.strftime("%H:%M:%S")
                        except:
                            pass
                    
                    decision = log.get("decision", "").lower()
                    source = log.get("source", "")
                    dest = log.get("dest", "")
                    risk = log.get("risk_score", 0)
                    tags = ", ".join(log.get("tags", []))
                    
                    # Обмежуємо довжину тегів, щоб уникнути переповнення рядка
                    if len(tags) > width - 60:
                        tags = tags[:width - 63] + "..."
                    
                    # Форматуємо рядок логу
                    log_line = f"{i}. [{timestamp}] {source} -> {dest} | "
                    
                    # Додаємо базову частину рядка
                    stdscr.addstr(log_start_row + i, 4, log_line)
                    
                    # Додаємо рішення з кольором
                    col_pos = 4 + len(log_line)
                    if decision == "blocked":
                        stdscr.attron(curses.color_pair(3))
                        stdscr.addstr("BLOCKED")
                        stdscr.attroff(curses.color_pair(3))
                    elif decision == "suspicious":
                        stdscr.attron(curses.color_pair(2))
                        stdscr.addstr("SUSPICIOUS")
                        stdscr.attroff(curses.color_pair(2))
                    else:
                        stdscr.attron(curses.color_pair(1))
                        stdscr.addstr("ALLOWED")
                        stdscr.attroff(curses.color_pair(1))
                    
                    # Додаємо решту інформації
                    stdscr.addstr(f" | Risk: {risk:.2f} | Tags: {tags}")
        
        # Нижній роздільник
        if height - 2 < height:
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(height - 2, 0, "=" * width)
            stdscr.attroff(curses.color_pair(4))
        
        # Підказки внизу екрана
        if height - 1 < height:
            help_text = " Q - Вихід | R - Скинути статистику "
            help_pos = max(0, (width - len(help_text)) // 2)
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(height - 1, 0, " " * width)
            stdscr.addstr(height - 1, help_pos, help_text)
            stdscr.attroff(curses.color_pair(5))


async def main():
    """
    Основна функція для запуску термінального моніторингу
    """
    parser = argparse.ArgumentParser(description="Термінальний інтерфейс для моніторингу SMPP Anomaly Detector")
    
    parser.add_argument("command", choices=["monitor"], help="Команда для виконання")
    parser.add_argument("--logs-dir", default="logs", help="Директорія з логами")
    parser.add_argument("--refresh", type=float, default=1.0, help="Інтервал оновлення (в секундах)")
    parser.add_argument("--text-mode", action="store_true", help="Використовувати текстовий режим замість curses")
    
    args = parser.parse_args()
    
    # Створюємо монітор
    monitor = TerminalMonitor(
        logs_dir=args.logs_dir,
        refresh_interval=args.refresh
    )
    
    try:
        # Підключаємось до Redis
        await monitor.connect()
        
        # Запускаємо відповідний режим
        if args.command == "monitor":
            if args.text_mode or not sys.stdout.isatty():
                # Текстовий режим
                await monitor.run_text_mode()
            else:
                # Режим curses
                curses.wrapper(lambda stdscr: asyncio.run(monitor.run_curses_mode(stdscr)))
        
    except Exception as e:
        print(f"Помилка: {e}")
    finally:
        # Закриваємо з'єднання
        await monitor.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
