import datetime
import logging
import os
import sys
import termcolor

__all__ = ['setup_logger']

logger_initialized = []


def setup_logger(name, output=None):
    logger = logging.getLogger(name)
    if name in logger_initialized:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = "[%(asctime2)s %(levelname2)s]%(module2)s:%(funcName2)s:%(lineno2)s - %(message2)s"
    color_formatter = ColoredFormatter(formatter, datefmt="%m/%d %H:%M:%S")

    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(color_formatter)
    logger.addHandler(ch)

    if output is not None:
        if output.endswith(".txt") or output.endswith(".log"):
            filename = output
        else:
            filename = os.path.join(output, "log.txt")
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        fh = logging.FileHandler(filename, mode='a', encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter())
        logger.addHandler(fh)
    logger_initialized.append(name)
    return logger


COLORS = {
    "WARNING": "yellow",
    "INFO": "white",
    "DEBUG": "blue",
    "CRITICAL": "red",
    "ERROR": "red",
}


class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt, datefmt, use_color=True):
        logging.Formatter.__init__(self, fmt, datefmt=datefmt)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            def colored(text):
                return termcolor.colored(
                    text,
                    color=COLORS[levelname],
                    attrs={"bold": True},
                )

            record.levelname2 = colored("{:<7}".format(record.levelname))
            record.message2 = colored(record.msg)

            asctime2 = datetime.datetime.fromtimestamp(record.created)
            record.asctime2 = termcolor.colored(asctime2, color="green")

            record.module2 = termcolor.colored(record.module, color="cyan")
            record.funcName2 = termcolor.colored(record.funcName, color="cyan")
            record.lineno2 = termcolor.colored(record.lineno, color="cyan")
        return logging.Formatter.format(self, record)
