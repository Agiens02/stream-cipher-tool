import json

from pymongo import MongoClient, errors

from utils.logger import setup_logger

logger = setup_logger(__name__)


class MongoDatabase:
    def __init__(self, db_uri, db_name):
        try:
            self.client = MongoClient(db_uri)
            self.db = self.client[db_name]
            self.collection = self.db['users']
            self.__init_db()
            logger.info("已连接到数据库")
        except errors.PyMongoError as e:
            logger.error(f"无法连接到数据库: {e}")
            self.client = None
            self.db = None
            self.collection = None

    def get_user(self, username):
        if self.collection is not None:
            return self.collection.find_one({"username": username})
        else:
            return None

    def all_info(self):
        if self.collection is not None:
            return list(self.collection.find())
        else:
            return []

    def login(self, username, password):
        info = self.get_user(username)
        if info is not None:
            logger.info(f"返回数据：{info}")
            if info["password"] == password:
                try:
                    return {
                        "username": info["username"],
                        "password": info["password"],
                        "a5_keys": info["a5_keys"],
                        "rc4_keys": info["rc4_keys"],
                        "chacha20_keys": info["chacha20_keys"]
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
                self.collection.insert_one({
                    "username": username,
                    "password": password,
                    "a5_keys": a5_keys,
                    "rc4_keys": rc4_keys,
                    "chacha20_keys": chacha20_keys
                })
                logger.info(f"用户注册: {username}")
                return True
            except errors.PyMongoError as e:
                logger.error(f"注册用户时出错: {e}")
                return False
        else:
            logger.error(f"已存在用户: {username}")
            return False

    def delete_user(self, username):
        try:
            result = self.collection.delete_one({"username": username})
            if result.deleted_count > 0:
                logger.info(f"用户删除: {username}")
                return True
            else:
                logger.error(f"用户未找到: {username}")
                return False
        except errors.PyMongoError as e:
            logger.error(f"删除用户时出错: {e}")
            return False

    def update_user(self, username, password=None, a5_keys=None, rc4_keys=None, chacha20_keys=None):
        updates = {}
        if password:
            updates["password"] = password
        if a5_keys:
            updates["a5_keys"] = a5_keys
        if rc4_keys:
            updates["rc4_keys"] = rc4_keys
        if chacha20_keys:
            updates["chacha20_keys"] = chacha20_keys

        if not updates:
            logger.error("没有更新的内容")
            return False

        try:
            result = self.collection.update_one(
                {"username": username},
                {"$set": updates}
            )
            if result.matched_count > 0:
                logger.info(f"用户更新: {username}")
                return True
            else:
                logger.error(f"用户未找到: {username}")
                return False
        except errors.PyMongoError as e:
            logger.error(f"更新用户时出错: {e}")
            return False

    def __init_db(self):
        try:
            # 检查表是否存在，MongoDB中的集合在插入数据时自动创建
            if 'users' not in self.db.list_collection_names():
                logger.info("Creating collection")
                self.db.create_collection('users')
            # 检查表结构是否符合预期
            # MongoDB是非结构化数据库，这里仅做提示
            logger.info("Checking collection structure")
        except errors.PyMongoError as e:
            logger.error(f"初始化数据库时出错: {e}")


if __name__ == '__main__':
    db = MongoDatabase('mongodb://localhost:27017/', 'user_database')
    # 示例注册一个用户
    registered = db.register('test', 'test_password', 'a5_key_value', 'rc4_key_value', 'chacha20_key_value')
    if registered:
        logger.info("用户注册成功")
    else:
        logger.info("用户已存在")

    # 示例登录
    login_result = db.login('test', 'test_password')
    if login_result:
        logger.info("登录成功！")
        logger.info(f"用户信息: {login_result['username']}")
    else:
        logger.info("登录失败！")

    # 示例更新
    updated = db.update_user('test', password='new_password')
    if updated:
        logger.info("用户更新成功")
    else:
        logger.info("用户更新失败")

    # 示例删除
    deleted = db.delete_user('root')
    if deleted:
        print(db.all_info())
        logger.info("用户删除成功")
    else:
        logger.info("用户删除失败")
