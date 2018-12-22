#!/usr/bin/env python
# -*- coding:UTF-8 -*-
#

import time


class CovLog(object):
    def info(self, msg):
        print("【Info %s】 %s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), msg))

    def error(self, msg):
        print("【Error %s】 %s" % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), msg))
