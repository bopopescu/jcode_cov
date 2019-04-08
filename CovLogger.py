#!/usr/bin/env python
# -*- coding:UTF-8 -*-
#

import os
import pathlib
import logging
import logging.handlers
from qcs_env_coverage.venv import colorlog

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__)))
PROJECT_NAME = os.path.basename(PROJECT_ROOT)

LOG_DIR = os.path.join(PROJECT_ROOT, "out")
default_log_file = os.path.join(LOG_DIR, "{}.log".format(PROJECT_NAME))


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

        if log_file:
            f_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=16732,
                backupCount=5,
            )
            f_handler.setLevel(logging.DEBUG)
            f_handler.setFormatter(formatter)
            mylogger.addHandler(f_handler)

        return mylogger


# Setup default logger
pathlib.Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
logger = CoverageLog.get_logger(name=PROJECT_NAME, log_file=default_log_file)
