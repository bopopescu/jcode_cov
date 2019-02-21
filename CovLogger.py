#!/usr/bin/env python
# -*- coding:UTF-8 -*-
#

import os
import types
import logging
from qcs_env_coverage.CovUtils import time_now
from qcs_env_coverage.venv import colorlog


def h1(self, title):
    self.info('=' * 120)
    self.info(title.upper())
    self.info('=' * 120)


def h2(self, title):
    self.info('=' * 100)
    self.info(title.upper())
    self.info('=' * 100)


def h3(self, title):
    self.info('=' * 80)
    self.info(title.upper())
    self.info('=' * 80)


def sep1(self):
    self.info('-' * 80)


def sep2(self):
    self.info('-' * 60)


def sep3(self):
    self.info('-' * 40)


def _decorate_logger(logger):
    """
    Decorate logger with custom methods
    """
    logger.h1 = types.MethodType(h1, logger)
    logger.h2 = types.MethodType(h2, logger)
    logger.h3 = types.MethodType(h3, logger)
    logger.sep1 = types.MethodType(sep1, logger)
    logger.sep2 = types.MethodType(sep2, logger)
    logger.sep3 = types.MethodType(sep3, logger)


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, 'out')
default_log_file = os.path.join(LOG_DIR, '{}.log'.format(time_now()))


class CoverageLog(object):
    @classmethod
    def get_logger(cls, name=None, log_file=default_log_file):
        # Get root logger if name is None
        mylogger = colorlog.getLogger(name)
        mylogger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s] - %(message)s')
        color_formatter = formatter = colorlog.ColoredFormatter(
            "%(log_color)s[%(asctime)s][%(levelname)s] - %(message)s",
            datefmt=None,
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'blue',
                'WARNING': 'purple',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            },
            secondary_log_colors={},
            style='%'
        )

        ch = colorlog.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(color_formatter)
        mylogger.addHandler(ch)

        if log_file is not None:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            mylogger.addHandler(fh)

        _decorate_logger(mylogger)
        return mylogger


# Setup default logger
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
logger = CoverageLog.get_logger(name='Default', log_file=default_log_file)
_decorate_logger(logger)
