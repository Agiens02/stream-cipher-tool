import argparse
import functools
import sqlite3
import json

import yaml

from utils.logger import setup_logger

logger = setup_logger(__name__)


class SQLDatabase:
    def __init__(self, db_path):
        try:
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
            self.__init_db()
            logger.info("已连接到数据库")
        except sqlite3.Error as e:
            logger.error(f"无法连接到数据库: {e}")
            self.conn = None
            self.cursor = None

    def get_user(self, username):
        if self.conn is not None:
            self.cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            return self.cursor.fetchone()
        else:
            return None

    def all_info(self):
        self.cursor.execute("SELECT * FROM users")
        rows = self.cursor.fetchall()
        return rows

    def login(self, username, password):
        info = self.get_user(username)
        if info is not None:
            logger.info(f"返回数据：{info}")
            if info[1] == password:
                try:
                    return {
                        "username": info[0],
                        "password": info[1],
                        "a5_keys": info[2],
                        "rc4_keys": info[3],
                        "chacha20_keys": info[4]  # Assuming chacha20_keys is at index 4
                    }
                except json.JSONDecodeError as e:
                    logger.error(f"无法格式化为JSON: {e}")
                    return False
            else:
                return False
        else:
            return False

    def register(self, username, password, a5_keys, rc4_keys, chacha20_keys):
        if self.get_user(username) is None:
            try:
                self.cursor.execute(
                    "INSERT INTO users (username, password, a5_keys, rc4_keys, chacha20_keys) VALUES (?, ?, ?, ?, ?)",
                    (username, password, a5_keys, rc4_keys, chacha20_keys))
                self.conn.commit()
                logger.info(f"用户注册: {username}")
                return True
            except sqlite3.Error as e:
                logger.error(f"注册用户时出错: {e}")
                return False
        else:
            logger.error(f"已存在用户: {username}")
            return False

    def delete_user(self, username):
        try:
            self.cursor.execute("DELETE FROM users WHERE username=?", (username,))
            self.conn.commit()
            logger.info(f"用户删除: {username}")
            return True
        except sqlite3.Error as e:
            logger.error(f"删除用户时出错: {e}")
            return False

    def update_user(self, username, password=None, a5_keys=None, rc4_keys=None, chacha20_keys=None):
        updates = []
        parameters = []
        if password:
            updates.append("password=?")
            parameters.append(password)
        if a5_keys:
            updates.append("a5_keys=?")
            parameters.append(a5_keys)
        if rc4_keys:
            updates.append("rc4_keys=?")
            parameters.append(rc4_keys)
        if chacha20_keys:
            updates.append("chacha20_keys=?")
            parameters.append(chacha20_keys)

        parameters.append(username)
        update_query = "UPDATE users SET " + ", ".join(updates) + " WHERE username=?"
        try:
            self.cursor.execute(update_query, tuple(parameters))
            self.conn.commit()
            logger.info(f"用户更新: {username}")
            return True
        except sqlite3.Error as e:
            logger.error(f"更新用户时出错: {e}")
            return False

    def __init_db(self):
        try:
            # 检查表是否存在
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            table_exists = self.cursor.fetchone()
            if not table_exists:
                logger.info("Creating table")
                self.cursor.execute('''
                    CREATE TABLE users (
                        username VARCHAR(20) PRIMARY KEY,
                        password VARCHAR(20),
                        a5_keys VARCHAR(50),
                        rc4_keys VARCHAR(50),
                        chacha20_keys VARCHAR(50)
                    )
                ''')
                self.conn.commit()
            else:
                # 检查表结构是否符合预期
                self.cursor.execute("PRAGMA table_info(users)")
                columns_info = self.cursor.fetchall()
                columns = [col_info[1] for col_info in columns_info]  # 获取所有列的名称
                expected_columns = ['username', 'password', 'a5_keys', 'rc4_keys', 'chacha20_keys']
                if columns != expected_columns:
                    logger.warning("Detected inconsistent table structure. Recreating table.")
                    self.cursor.execute("DROP TABLE users")
                    self.cursor.execute('''
                        CREATE TABLE users (
                            username VARCHAR(20) PRIMARY KEY,
                            password VARCHAR(20),
                            a5_keys VARCHAR(50),
                            rc4_keys VARCHAR(50),
                            chacha20_keys VARCHAR(50)
                        )
                    ''')
                    self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"初始化数据库时出错: {e}")


if __name__ == '__main__':
    db = SQLDatabase('../res/users.db')
    # 示例注册一个用户
    registered = db.register('tes', 'test_password', 'a5_key_value', 'rc4_key_value', 'chacha20_key_value')
    if registered:
        logger.info("用户注册成功")
    else:
        logger.info("用户已存在")

    # 示例登录
    login_result = db.login('tes', 'test_password')
    if login_result:
        logger.info("登录成功！")
        logger.info(f"用户信息: {login_result['username']}")
    else:
        logger.info("登录失败！")

    # 示例更新
    updated = db.update_user('tes', password='new_password', a5_keys='0211061021515', chacha20_keys='12315615645')
    if updated:
        logger.info(f"用户信息: {db.get_user('tes')}")
        logger.info("用户更新成功")
    else:
        logger.info("用户更新失败")

    # 示例删除
    deleted = db.delete_user('tes')
    if deleted:
        logger.info("用户删除成功")
    else:
        logger.info("用户删除失败")
