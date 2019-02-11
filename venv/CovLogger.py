#!/usr/bin/env python
# -*- coding:UTF-8 -*-
#


class CoverageLogger(object):
    """Coverage logger"""

    def info(self, msg, local_time=None):
        if not local_time:
            print("【Info】 {}".format(msg))
        print("【Info {}】 {}".format(local_time, msg))

    def error(self, msg, local_time=None):
        if not local_time:
            print("【Error】 {}".format(msg))
        print("【Error {}】 {}".format(local_time, msg))
