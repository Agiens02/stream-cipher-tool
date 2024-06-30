import argparse
import functools
import re
import sys
from datetime import datetime

import yaml
from PyQt5.QtCore import pyqtSlot, Qt
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QComboBox, QTabWidget, QFileDialog, QMainWindow, QStatusBar, QGridLayout, QDialog, QMessageBox, QTableWidget,
    QTableWidgetItem, QFrame
)

from algorithm.A5_1 import *
from algorithm.RC4 import *
from utils.utils import generate_key
from algorithm.ChaCha20 import ChaCha20
from utils.utils import print_arguments, add_arguments, dict_to_object
from database.SQLite import SQLDatabase
from database.MongoDB import MongoDatabase
from utils.logger import setup_logger

parser = argparse.ArgumentParser(description=__doc__)
add_arg = functools.partial(add_arguments, argparser=parser)
add_arg('configs', str, 'database/config.yml', '配置文件')
args = parser.parse_args()
print_arguments(args)
configs = args.configs

if isinstance(configs, str):
    with open(configs, 'r', encoding='utf-8') as f:
        configs = yaml.load(f.read(), Loader=yaml.FullLoader)
    print_arguments(configs=configs)
configs = dict_to_object(configs)

logger = setup_logger(__name__)
if configs.database.database_type == 'mongodb':
    database = MongoDatabase(configs.database.mongodb.url, configs.database.mongodb.db_name)
    cursor = None
else:
    database = SQLDatabase('res/users.db')
    cursor = database.cursor

ABOUT = """
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>流密码加密解密工具</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
        }
        h3 {
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            text-align: center;
        }
        .footer {
            position: relative;
            bottom: 0;
            text-align: center;
            font-size: 0.9em;
            color: #999;
        }
    </style>
</head>
<body>
    <h3>流密码加密解密工具 | 版本v1.0.0</h3>
    <p>这是一个用于加密和解密文本的工具，支持A5、RC4和ChaCha20。</p>
    <p><a href="https://github.com/Agiens02/stream-cipher-tool" target="_blank">项目地址</a><p>
    <div class="footer">
        <p>版权所有 &copy; 2024 <a href="https://github.com/Agiens02" target="_blank">Agiens02</a></p>
    </div>
</body>
</html>
        """


def encrypt_a5(plaintext, key):
    encryptor = A5_1()
    encrypt_text = encryptor.encrypt(plaintext, key)
    return encrypt_text


def encrypt_rc4(plaintext, key):
    encryptor = RC4(key)
    encrypt_text = encryptor.encrypt(plaintext)
    return encrypt_text


def decrypt_a5(ciphertext, key):
    decryptor = A5_1()
    decrypt_text = decryptor.decrypt(ciphertext, key)
    return decrypt_text


def decrypt_rc4(ciphertext, key):
    decryptor = RC4(key)
    decrypt_text = decryptor.decrypt(ciphertext)
    return decrypt_text


def decrypt_chacha20(ciphertext, key):
    decryptor = ChaCha20(key=key)
    ciphertext = bytes.fromhex(ciphertext)
    decrypt_text = decryptor.decrypt(ciphertext)
    return decrypt_text


def encrypt_chacha20(plaintext, key):
    decryptor = ChaCha20(key=key)
    decrypt_text = decryptor.encrypt(plaintext.encode('utf-8'))
    return decrypt_text.hex()


class AdminLoginWindow(QDialog):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle('管理员登录')
        logger.info('管理员登录')
        self.font = QFont('黑体', 8)
        self.setFont(self.font)
        self.setFixedSize(300, 150)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        entry_layout = QHBoxLayout()
        self.password_label = QLabel('管理密码:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        entry_layout.addWidget(self.password_label)
        entry_layout.addWidget(self.password_input)
        self.login_button = QPushButton('登录')
        self.login_button.clicked.connect(self.check_password)

        layout.addLayout(entry_layout)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def check_password(self):
        if self.password_input.text() == configs.database.admin_password:
            self.accept()
            self.open_admin_window()
        else:
            QMessageBox.warning(self, '错误', '密码错误，请重试。')

    def open_admin_window(self):
        self.admin_window = AdminWindow(self.main_window)
        self.admin_window.show()


class AdminWindow(QMainWindow):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.setWindowTitle('管理界面')
        logger.info('管理员界面')
        self.main_window = main_window
        self.width = 850
        self.height = 600
        self.font = QFont('黑体', 9)
        self.setFont(self.font)
        self.setMinimumWidth(self.width)
        self.setMinimumHeight(self.height)
        self.database = database
        self.cursor = cursor
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.tableWidget = QTableWidget()
        self.initUI()

    def initUI(self):
        self.layout = QVBoxLayout()
        self.createTable()
        self.layout.addWidget(self.tableWidget)

        self.buttonLoad = QPushButton("加载数据")
        self.buttonLoad.clicked.connect(self.loadData)
        self.layout.addWidget(self.buttonLoad)

        self.buttonDelete = QPushButton("删除选中用户")
        self.buttonDelete.clicked.connect(self.deleteUser)
        self.layout.addWidget(self.buttonDelete)
        self.buttonSave = QPushButton("保存更改")

        self.buttonSave.clicked.connect(self.saveChanges)
        self.layout.addWidget(self.buttonSave)

        self.container = QWidget()
        self.container.setLayout(self.layout)
        self.setCentralWidget(self.container)

    def createTable(self):
        self.tableWidget = QTableWidget()
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(5)
        self.tableWidget.setHorizontalHeaderLabels(["用户名", '密码', "A5密钥", "RC4密钥", "ChaCha20密钥"])
        self.loadData()
        self.tableWidget.setEditTriggers(QTableWidget.AllEditTriggers)
        self.tableWidget.setColumnWidth(0, 100)
        self.tableWidget.setColumnWidth(1, 130)
        self.tableWidget.setColumnWidth(2, 200)
        self.tableWidget.setColumnWidth(3, 300)
        self.tableWidget.setColumnWidth(4, 300)
        self.show_status_message("数据加载成功")

    def closeEvent(self, event):
        self.main_window.setEnabled(True)
        super().closeEvent(event)

    def deleteUser(self):
        if self.tableWidget.currentRow() >= 0:
            username_item = self.tableWidget.item(self.tableWidget.currentRow(), 0)
            username = username_item.text() if username_item is not None else "未知用户"

            # 创建确认对话框
            reply = QMessageBox.question(self, '确认删除', f'你确定要删除用户 {username} 吗?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                self.tableWidget.removeRow(self.tableWidget.currentRow())

                if self.cursor:
                    self.cursor.execute("DELETE FROM users WHERE username=?", (username,))
                    self.database.conn.commit()
                else:
                    self.database.delete_user(username)

                logger.info(f"删除用户{username}")
                self.show_status_message(f"用户{username}已删除")
            else:
                logger.info("取消删除用户")
                self.show_status_message("取消删除用户")
        else:
            logger.info("未选择用户")
            self.show_status_message("未选择用户")

    def saveChanges(self):
        if self.cursor:
            self.cursor.execute("DELETE FROM users")
            for row in range(self.tableWidget.rowCount()):
                username = self.tableWidget.item(row, 0).text()
                password = self.tableWidget.item(row, 1).text()
                a5_keys = self.tableWidget.item(row, 2).text()
                rc4_keys = self.tableWidget.item(row, 3).text()
                chacha20_keys = self.tableWidget.item(row, 4).text()
                self.cursor.execute(
                    "INSERT INTO users (username, password, a5_keys, rc4_keys,chacha20_keys) VALUES (?, ?, ?, ?,?)",
                    (username, password, a5_keys, rc4_keys))
            self.database.conn.commit()
        else:
            self.database.collection.delete_many({})
            for row in range(self.tableWidget.rowCount()):
                username = self.tableWidget.item(row, 0).text()
                password = self.tableWidget.item(row, 1).text()
                a5_keys = self.tableWidget.item(row, 2).text()
                rc4_keys = self.tableWidget.item(row, 3).text()
                chacha20_keys = self.tableWidget.item(row, 4).text()
                self.database.register(username, password, a5_keys, rc4_keys, chacha20_keys)

        logger.info("用户已更改")
        self.show_status_message("保存成功")

    def loadData(self):
        if self.cursor:
            self.cursor.execute("SELECT * FROM users")
            rows = self.cursor.fetchall()
        else:
            rows = list(self.database.collection.find({}, {"_id": 0, "username": 1, "password": 1, "a5_keys": 1,
                                                           "rc4_keys": 1, "chacha20_keys": 1}))

        self.tableWidget.setRowCount(len(rows))
        for i, row in enumerate(rows):
            if self.cursor:
                self.tableWidget.setItem(i, 0, QTableWidgetItem(row[0]))
                self.tableWidget.setItem(i, 1, QTableWidgetItem(row[1]))
                self.tableWidget.setItem(i, 2, QTableWidgetItem(row[2]))
                self.tableWidget.setItem(i, 3, QTableWidgetItem(row[3]))
                self.tableWidget.setItem(i, 4, QTableWidgetItem(row[4]))
            else:
                self.tableWidget.setItem(i, 0, QTableWidgetItem(row["username"]))
                self.tableWidget.setItem(i, 1, QTableWidgetItem(row["password"]))
                self.tableWidget.setItem(i, 2, QTableWidgetItem(row["a5_keys"]))
                self.tableWidget.setItem(i, 3, QTableWidgetItem(row["rc4_keys"]))
                self.tableWidget.setItem(i, 4, QTableWidgetItem(row["chacha20_keys"]))

        logger.info("加载用户数据")
        self.show_status_message("加载成功")

    def show_status_message(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.status_bar.showMessage(f"[{timestamp}] - {message}", -1)


class RegisterWindow(QDialog):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.database = database
        self.cursor = cursor
        self.main_window = main_window
        self.font = QFont('黑体', 9)
        self.setFont(self.font)
        self.setWindowTitle('注册')
        self.setMinimumWidth(380)
        self.setMinimumHeight(300)
        self.initUI()
        logger.info('注册页面初始化')

    def initUI(self):
        register_layout = QVBoxLayout()

        grid_layout = QGridLayout()

        self.register_name_label = QLabel('用户名:')
        self.register_name = QLineEdit()
        self.register_name.setPlaceholderText('请输入用户名')
        self.register_name_label.setBuddy(self.register_name)
        grid_layout.addWidget(self.register_name_label, 0, 0)
        grid_layout.addWidget(self.register_name, 0, 1)

        self.register_password_label = QLabel('密码:')
        self.register_password = QLineEdit()
        self.register_password.setEchoMode(QLineEdit.Password)
        self.register_password.setPlaceholderText('请输入密码')
        self.register_password_label.setBuddy(self.register_password)
        grid_layout.addWidget(self.register_password_label, 1, 0)
        grid_layout.addWidget(self.register_password, 1, 1)

        self.register_confirm_label = QLabel('确认密码:')
        self.register_confirm = QLineEdit()
        self.register_confirm.setEchoMode(QLineEdit.Password)
        self.register_confirm.setPlaceholderText('请再次输入密码')
        self.register_confirm_label.setBuddy(self.register_confirm)
        grid_layout.addWidget(self.register_confirm_label, 2, 0)
        grid_layout.addWidget(self.register_confirm, 2, 1)

        self.register_key1_label = QLabel('A5密钥')
        self.register_key1_input = QLineEdit()
        self.register_key1_label.setBuddy(self.register_key1_input)
        grid_layout.addWidget(self.register_key1_label, 3, 0)
        grid_layout.addWidget(self.register_key1_input, 3, 1)

        self.register_key2_label = QLabel('RC4密钥')
        self.register_key2_input = QLineEdit()
        self.register_key2_label.setBuddy(self.register_key2_input)
        grid_layout.addWidget(self.register_key2_label, 4, 0)
        grid_layout.addWidget(self.register_key2_input, 4, 1)

        self.register_key3_label = QLabel('ChaCha20密钥')
        self.register_key3_input = QLineEdit()
        self.register_key3_label.setBuddy(self.register_key3_input)
        grid_layout.addWidget(self.register_key3_label, 5, 0)
        grid_layout.addWidget(self.register_key3_input, 5, 1)

        btn_layout = QVBoxLayout()
        self.keys_gen = QPushButton('生成密钥')
        self.keys_gen.clicked.connect(self.generate_keys)
        self.register_confirm_button = QPushButton('注册')
        self.register_confirm_button.clicked.connect(self.register)
        self.register_cancel_button = QPushButton('取消')
        self.register_cancel_button.clicked.connect(self.reject)
        btn_layout.addWidget(self.keys_gen)
        btn_layout.addWidget(self.register_confirm_button)
        btn_layout.addWidget(self.register_cancel_button)

        register_layout.addLayout(grid_layout)
        register_layout.addLayout(btn_layout)
        self.setLayout(register_layout)

    def generate_keys(self):
        self.register_key1_input.setText(generate_key(1))
        self.register_key2_input.setText(generate_key(0))
        self.register_key3_input.setText(generate_key(2).hex())

    def show_message_box(self, title, message):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setFixedSize(300, 200)
        msg_box.setText(message)
        ok_button = msg_box.addButton("确定", QMessageBox.AcceptRole)
        msg_box.exec_()

    def register(self):
        user = self.register_name.text()
        psd = self.register_password.text() == self.register_confirm.text()
        if user == '':
            self.show_message_box('警告', '用户名不能为空')
        elif self.register_password.text() == '':
            self.show_message_box('警告', '密码不能为空')
        elif self.database.get_user(user) is not None:
            self.show_message_box('警告', '用户名已存在')
        elif not psd:
            self.show_message_box('警告', '密码不一致')
        elif len(self.register_key1_input.text()) != 18 or self.register_key2_input.text() == '':
            self.show_message_box('警告', '密钥错误')
        else:
            self.database.register(user, self.register_password.text(), self.register_key1_input.text(),
                                   self.register_key2_input.text(), self.register_key3_input.text())
            self.show_message_box('提示', '注册成功')
            self.accept()
            return

    def reject(self):
        self.register_key1_input.clear()
        self.register_key2_input.clear()
        self.main_window.setEnabled(True)
        super().reject()

    def closeEvent(self, event):
        self.register_key1_input.clear()
        self.register_key2_input.clear()
        self.main_window.setEnabled(True)
        super().closeEvent(event)


class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.database = database
        self.cursor = cursor
        self.icon = QIcon('res/icon.ico')
        self.setWindowIcon(self.icon)
        self.register_windows = None

    def initUI(self):
        self.setWindowTitle('流密码加密解密工具')
        self.font = QFont("Microsoft YaHei", 10)
        self.setFont(self.font)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.tabs = QTabWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        self.settings_tab = QWidget()
        self.about_tab = QWidget()

        self.tabs.addTab(self.encrypt_tab, '加密')
        self.tabs.addTab(self.decrypt_tab, '解密')
        self.tabs.addTab(self.settings_tab, '设置')
        self.tabs.addTab(self.about_tab, '关于')

        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_settings_tab()
        self.create_about_tab()

        self.setCentralWidget(self.tabs)

    def create_encrypt_tab(self):
        layout = QVBoxLayout()

        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(['A5', 'RC4', 'ChaCha20'])

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText('输入密钥/加载密钥')

        self.generate_key_btn = QPushButton('加载密钥')
        self.generate_key_btn.clicked.connect(self.get_key)
        self.generate_key_btn.setToolTip('如果登录密钥为空，则生成随机密钥')

        self.plaintext_input = QTextEdit()
        self.plaintext_input.setPlaceholderText('输入明文')

        self.import_plaintext_btn = QPushButton('导入明文')
        self.import_plaintext_btn.clicked.connect(self.import_plaintext)

        self.encrypt_btn = QPushButton('加密')
        self.encrypt_btn.clicked.connect(self.encrypt_text)

        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setPlaceholderText('加密后的密文')
        self.ciphertext_output.setReadOnly(True)

        self.save_ciphertext_btn = QPushButton('导出密文')
        self.save_ciphertext_btn.clicked.connect(self.save_ciphertext)

        layout.addWidget(self.algorithm_combo)
        layout.addWidget(self.key_input)
        layout.addWidget(self.generate_key_btn)

        encrypt_layout = QVBoxLayout()
        encrypt_layout.addWidget(QLabel('明文：'))
        encrypt_layout.addWidget(self.plaintext_input)
        encrypt_layout.addWidget(self.import_plaintext_btn)

        cipher_layout = QVBoxLayout()
        cipher_layout.addWidget(QLabel('密文：'))
        cipher_layout.addWidget(self.ciphertext_output)
        cipher_layout.addWidget(self.save_ciphertext_btn)

        text_layout = QHBoxLayout()
        text_layout.addLayout(encrypt_layout)
        text_layout.addLayout(cipher_layout)

        layout.addLayout(text_layout)
        layout.addWidget(self.encrypt_btn)

        self.algorithm_combo.currentIndexChanged.connect(self.combobox_changed)

        self.encrypt_tab.setLayout(layout)

    def create_decrypt_tab(self):
        layout = QVBoxLayout()

        self.dec_algorithm_combo = QComboBox()
        self.dec_algorithm_combo.addItems(['A5', 'RC4', 'ChaCha20'])

        self.dec_key_input = QLineEdit()
        self.dec_key_input.setPlaceholderText('输入密钥/加载密钥')
        self.dec_generate_key_btn = QPushButton('加载密钥')
        self.dec_generate_key_btn.clicked.connect(self.get_key)
        self.dec_generate_key_btn.setToolTip('如果登录密钥为空，则生成随机密钥')

        self.ciphertext_input = QTextEdit()
        self.ciphertext_input.setPlaceholderText('输入密文')
        self.ciphertext_import_btn = QPushButton('导入密文')
        self.ciphertext_import_btn.clicked.connect(self.import_ciphertext)
        self.decrypt_btn = QPushButton('解密')
        self.decrypt_btn.clicked.connect(self.decrypt_text)

        self.plaintext_output = QTextEdit()
        self.plaintext_output.setPlaceholderText('解密后的明文')
        self.save_ciphertext_btn = QPushButton('导出明文')
        self.save_ciphertext_btn.clicked.connect(self.save_plaintext)
        self.plaintext_output.setReadOnly(True)

        text_layout = QHBoxLayout()
        cipher_layout = QVBoxLayout()
        cipher_layout.addWidget(QLabel('密文：'))
        cipher_layout.addWidget(self.ciphertext_input)
        cipher_layout.addWidget(self.ciphertext_import_btn)
        plain_layout = QVBoxLayout()
        plain_layout.addWidget(QLabel('明文：'))
        plain_layout.addWidget(self.plaintext_output)
        plain_layout.addWidget(self.save_ciphertext_btn)
        text_layout.addLayout(cipher_layout)
        text_layout.addLayout(plain_layout)

        layout.addWidget(self.dec_algorithm_combo)
        layout.addWidget(self.dec_key_input)
        layout.addWidget(self.dec_generate_key_btn)
        layout.addLayout(text_layout)
        layout.addWidget(self.decrypt_btn)
        self.dec_algorithm_combo.currentIndexChanged.connect(self.dec_combobox_changed)
        self.decrypt_tab.setLayout(layout)

    def create_settings_tab(self):  # 设置页面
        layout = QVBoxLayout()
        label_layout = QGridLayout()

        self.username_label = QLabel('用户名:')
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('输入用户名')
        label_layout.addWidget(self.username_label, 0, 0)
        label_layout.addWidget(self.username_input, 0, 1)

        self.password_label = QLabel('密码:')
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('输入密码')
        self.password_input.setEchoMode(QLineEdit.Password)
        label_layout.addWidget(self.password_label, 1, 0)
        label_layout.addWidget(self.password_input, 1, 1)

        self.a5_key_label = QLabel('A5密钥:')
        self.a5_user_key = QComboBox()
        label_layout.addWidget(self.a5_key_label, 2, 0)
        label_layout.addWidget(self.a5_user_key, 2, 1)

        self.rc4_key_label = QLabel('RC4密钥:')
        self.rc4_user_key = QComboBox()
        label_layout.addWidget(self.rc4_key_label, 3, 0)
        label_layout.addWidget(self.rc4_user_key, 3, 1)

        self.chacha20_key_label = QLabel('ChaCha20密钥:')
        self.chacha20_user_key = QComboBox()
        label_layout.addWidget(self.chacha20_key_label, 4, 0)
        label_layout.addWidget(self.chacha20_user_key, 4, 1)

        btn_layout = QVBoxLayout()
        self.login_btn = QPushButton('登录')
        self.login_btn.clicked.connect(self.login_user)
        self.register_btn = QPushButton('注册')
        self.register_btn.clicked.connect(self.register_user)
        self.admin_btn = QPushButton('管理')
        self.admin_btn.clicked.connect(self.admin_user)
        btn_layout.addWidget(self.login_btn)
        btn_layout.addWidget(self.register_btn)
        btn_layout.addWidget(self.admin_btn)

        layout.addLayout(label_layout)
        layout.addLayout(btn_layout)
        self.settings_tab.setLayout(layout)

    def create_about_tab(self):
        html_content = ABOUT

        about_tab_content = QLabel()
        about_tab_content.setText(html_content)
        about_tab_content.setTextFormat(Qt.RichText)
        about_tab_content.setOpenExternalLinks(True)

        layout = QVBoxLayout()
        layout.addWidget(about_tab_content)

        self.about_tab.setLayout(layout)

    def create_separator(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def admin_user(self):
        self.admin_windows = AdminLoginWindow(self)
        self.admin_windows.exec_()

    def register_user(self):
        if self.register_windows is None:
            self.register_windows = RegisterWindow(self)
        self.register_windows.exec_()

    def login_user(self):
        if self.username_input.text() != '' and self.password_input.text() != '':
            result = self.database.login(self.username_input.text(), self.password_input.text())
            if result:
                try:
                    self.a5_user_key.clear()
                    self.rc4_user_key.clear()
                    self.a5_user_key.addItem(result["a5_keys"])
                    self.rc4_user_key.addItem(result["rc4_keys"])
                    self.chacha20_user_key.addItem(result["chacha20_keys"])
                    if self.algorithm_combo.currentText() == 'A5':
                        self.key_input.setText(result["a5_keys"])
                    elif self.algorithm_combo.currentText() == 'RC4':
                        self.key_input.setText(result["rc4_keys"])
                    else:
                        self.chacha20_user_key.addItem(result["chacha20_keys"])
                    if self.dec_algorithm_combo.currentText() == 'A5':
                        self.dec_key_input.setText(result["a5_keys"])
                    elif self.dec_algorithm_combo.currentText() == 'RC4':
                        self.dec_key_input.setText(result["rc4_keys"])
                    else:
                        self.chacha20_user_key.addItem(result["chacha20_keys"])
                    self.show_status_message('登录成功')
                except:
                    self.show_status_message('登录失败')
            else:
                self.show_status_message('用户名或密码错误')
        else:
            self.show_status_message('用户名/密码不能为空')

    def combobox_changed(self, index):
        self.key_input.clear()

    def dec_combobox_changed(self, index):
        self.dec_key_input.clear()

    @pyqtSlot()
    def get_key(self):
        key = ''
        algorithm = ''
        input_k = ''
        tab = self.tabs.currentIndex()
        if tab == 0:
            algorithm = self.algorithm_combo.currentText()
            input_k = self.key_input
        elif tab == 1:
            algorithm = self.dec_algorithm_combo.currentText()
            input_k = self.dec_key_input
        if algorithm == 'A5':
            if self.a5_user_key.count() != 0:
                key = self.a5_user_key.currentText()

                self.show_status_message("加载密钥成功")
            else:
                key = generate_key(1)
                self.show_status_message("随机生成密钥成功")
        elif algorithm == 'RC4':
            if self.rc4_user_key.count() != 0:
                key = self.rc4_user_key.currentText()
                self.show_status_message("加载密钥成功")
            else:
                key = generate_key(0)
                self.show_status_message("随机生成密钥成功")
        else:
            if self.chacha20_user_key.count() != 0:
                key = self.chacha20_user_key.currentText()
                self.show_status_message("加载密钥成功")
            else:
                key = generate_key(2).hex()
                self.show_status_message("随机生成密钥成功")
        input_k.setText(key)

    @pyqtSlot()
    def import_plaintext(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, '导入明文txt文件', '', 'Text Files (*.txt);;All Files (*)',
                                                   options=options)
        if file_name:
            with open(file_name, 'r', encoding='utf-8') as file:
                self.plaintext_input.setPlainText(file.read())
            self.show_status_message("导入明文成功")

    @pyqtSlot()
    def import_ciphertext(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, '导入密文txt文件', '', 'Text Files (*.txt);;All Files (*)',
                                                   options=options)
        if file_name:
            with open(file_name, 'r', encoding='utf-8') as file:
                self.ciphertext_input.setPlainText(file.read())
            self.show_status_message("导入密文成功")

    @pyqtSlot()
    def save_ciphertext(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, '保存密文txt文件', '', 'Text Files (*.txt);;All Files (*)',
                                                   options=options)
        if file_name:
            with open(file_name, 'w', encoding='utf-8') as file:
                file.write(self.ciphertext_output.toPlainText())
            self.show_status_message("保存密文成功")

    @pyqtSlot()
    def save_plaintext(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, '保存明文txt文件', '', 'Text Files (*.txt);;All Files (*)',
                                                   options=options)
        if file_name:
            with open(file_name, 'w', encoding='utf-8') as file:
                file.write(self.plaintext_output.toPlainText())
            self.show_status_message("保存明文成功")

    @pyqtSlot()
    def encrypt_text(self):
        algorithm = self.algorithm_combo.currentText()
        key = self.key_input.text()
        if key == '':
            self.show_status_message("未输入密钥")
            return
        plaintext = self.plaintext_input.toPlainText()
        if plaintext == '':
            self.show_status_message("未输入明文")
            return
        if algorithm == 'A5':
            try:
                ciphertext = encrypt_a5(plaintext, key)
            except Exception as e:
                self.show_status_message('加密失败，请检查密钥和算法')
                return
        elif algorithm == 'RC4':
            try:
                if key.startswith('0x') and len(key) == 18:
                    # 创建一个QMessageBox实例
                    msg_box = QMessageBox(self)
                    msg_box.setWindowTitle("提示")
                    msg_box.setText("检测到A5格式的密钥，是否继续使用RC4算法加密？")
                    # 创建自定义按钮并设置文本
                    yes_button = msg_box.addButton("是", QMessageBox.YesRole)
                    no_button = msg_box.addButton("否", QMessageBox.NoRole)
                    # 显示消息框
                    msg_box.exec_()

                    # 根据用户选择的按钮执行相应的操作
                    if msg_box.clickedButton() == yes_button:
                        ciphertext = encrypt_rc4(plaintext, key)
                    else:
                        self.show_status_message('加密已取消')
                        return
                else:
                    ciphertext = encrypt_rc4(plaintext, key)
            except Exception as e:
                self.show_status_message('加密失败，请检查密钥和算法')
                return
        elif algorithm == 'ChaCha20':
            ciphertext = encrypt_chacha20(plaintext, bytes.fromhex(key))
        else:
            ciphertext = ''
        self.ciphertext_output.setPlainText(ciphertext)
        self.show_status_message("加密成功")

    @pyqtSlot()
    def decrypt_text(self):
        algorithm = self.dec_algorithm_combo.currentText()
        key = self.dec_key_input.text()
        ciphertext = self.ciphertext_input.toPlainText()
        if key == '':
            self.show_status_message("未输入密钥")
            return
        if ciphertext == '':
            self.show_status_message("未输入密文")
            return
        if (len(key) != 18) and algorithm == 'A5':
            if key.startswith('0x'):
                self.show_status_message("A5密钥长度错误")
            return
        try:
            if algorithm == 'A5':
                plaintext = decrypt_a5(ciphertext, key)
            elif algorithm == 'RC4':
                plaintext = decrypt_rc4(ciphertext, key)
            elif algorithm == 'ChaCha20':
                plaintext = decrypt_chacha20(ciphertext, bytes.fromhex(key))
            else:
                plaintext = ''
            self.plaintext_output.setPlainText(plaintext)
            self.show_status_message("解密成功")
        except Exception as e:
            self.show_status_message(f"解密失败，请检查密钥和算法")

    @pyqtSlot()
    def show_status_message(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.status_bar.showMessage(f"[{timestamp}] - {message}", -1)


if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        ex = CryptoApp()
        ex.show()
        sys.exit(app.exec_())
    finally:
        logger.info("程序退出")
        if cursor is not None:
            database.cursor.close()
            database.conn.close()
