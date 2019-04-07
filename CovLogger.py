#!/usr/bin/env python
# -*- coding:UTF-8 -*-
#

import os
import types
import logging
import logging.handlers
from qcs_env_coverage.venv import colorlog

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__)))
PROJECT_NAME = os.path.basename(PROJECT_ROOT)

LOG_DIR = os.path.join(PROJECT_ROOT, "out")
default_log_file = os.path.join(LOG_DIR, "{}.log".format(PROJECT_NAME))


def h1(self, title):
    self.info("=" * 120)
    self.info(title.upper())
    self.info("=" * 120)


def h2(self, title):
    self.info("=" * 100)
    self.info(title.upper())
    self.info("=" * 100)


def h3(self, title):
    self.info("=" * 80)
    self.info(title.upper())
    self.info("=" * 80)


def sep1(self):
    self.info("-" * 80)


def sep2(self):
    self.info("-" * 60)


def sep3(self):
    self.info("-" * 40)


def _decorate_logger(logger):
    """
    Decorate logger with custom methods
    :param logger:
    """
    logger.h1 = types.MethodType(h1, logger)
    logger.h2 = types.MethodType(h2, logger)
    logger.h3 = types.MethodType(h3, logger)
    logger.sep1 = types.MethodType(sep1, logger)
    logger.sep2 = types.MethodType(sep2, logger)
    logger.sep3 = types.MethodType(sep3, logger)


class CoverageLog(object):
    @classmethod
    def get_logger(cls, name=None, log_file=default_log_file):
        """
        Coverage logger with a default colored formatter
        :param name:
        :param log_file:
        :return:
        """
        # Get root logger if name is None
        mylogger = colorlog.getLogger(name)
        mylogger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(asctime)s][%(levelname)s] - %(message)s")
        color_formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(asctime)s][%(levelname)s] - %(message)s",
            datefmt=None,
            reset=True,
            log_colors={
                "DEBUG": "cyan",
                "INFO": "blue",
                "WARNING": "purple",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
            secondary_log_colors={},
            style="%"
        )

        s_handler = colorlog.StreamHandler()
        s_handler.setLevel(logging.DEBUG)
        s_handler.setFormatter(color_formatter)
        mylogger.addHandler(s_handler)

        if log_file is not None:
            f_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=16732,
                backupCount=5,
            )
            f_handler.setLevel(logging.DEBUG)
            f_handler.setFormatter(formatter)
            mylogger.addHandler(f_handler)

        _decorate_logger(mylogger)
        return mylogger


# Setup default logger
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
logger = CoverageLog.get_logger(name="DefaultCoverage", log_file=default_log_file)
_decorate_logger(logger)
