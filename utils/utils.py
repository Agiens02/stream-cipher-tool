import argparse
import distutils.util
import functools
import secrets
import string
from .logger import setup_logger

logger = setup_logger(__name__)


def generate_key(mode):
    if mode == 0:  # RC4加密算法
        characters = string.ascii_letters + string.digits + string.punctuation
        key = ''.join(secrets.choice(characters) for i in range(32))
    elif mode == 1:  # A5_1加密算法
        key = '0x' + secrets.token_hex(8)
    elif mode == 2:  # ChaCha20加密算法
        key = secrets.token_bytes(32)
    else:
        key = None
    return key


def print_arguments(args=None, configs=None):
    if args:
        logger.info("----------- 配置文件参数 -----------")
        for arg, value in sorted(vars(args).items()):
            logger.info("%s: %s" % (arg, value))
        logger.info("------------------------------------------------")
    if configs:
        logger.info("----------- 配置文件参数 -----------")
        for arg, value in sorted(configs.items()):
            if isinstance(value, dict):
                logger.info(f"{arg}:")
                for a, v in sorted(value.items()):
                    if isinstance(v, dict):
                        logger.info(f"\t{a}:")
                        for a1, v1 in sorted(v.items()):
                            logger.info("\t\t%s: %s" % (a1, v1))
                    else:
                        logger.info("\t%s: %s" % (a, v))
            else:
                logger.info("%s: %s" % (arg, value))
        logger.info("------------------------------------------------")


def add_arguments(argname, type, default, help, argparser, **kwargs):
    type = distutils.util.strtobool if type == bool else type
    argparser.add_argument("--" + argname,
                           default=default,
                           type=type,
                           help=help + ' 默认: %(default)s.',
                           **kwargs)


class Dict(dict):
    __setattr__ = dict.__setitem__
    __getattr__ = dict.__getitem__


def dict_to_object(dict_obj):
    if not isinstance(dict_obj, dict):
        return dict_obj
    inst = Dict()
    for k, v in dict_obj.items():
        inst[k] = dict_to_object(v)
    return inst
