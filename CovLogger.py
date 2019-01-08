#!/usr/bin/env python
# -*- coding:UTF-8 -*-
#

from datetime import datetime


class CoverageLogger(object):
    def __init__(self):
        self.local_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

    def info(self, msg):
        print("【Info {}】 {}".format(self.local_time, msg))

    def error(self, msg):
        print("【Error {}】 {}".format(self.local_time, msg))
