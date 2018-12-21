#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#


__author__ = "wangdongsheng"
__email__ = "wangdongsheng@baidu.com"
__version__ = "1.0.0"

import os
import time
import datetime
import subprocess

from thirdparts import pexpect


def remote_cmd(remote, passwd, cmd):
    ssh_cmd = 'ssh ' + remote + " \"" + cmd + "\""
    ssh = pexpect.spawn('/bin/bash', ['-c', ssh_cmd], timeout=10)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(['\(yes/no\)\?', 'assword:'])
            if not ssh.isalive() and index == 0:
                print("run ssh cmd success")
                return 0
            if index == 0:
                ssh.sendline("yes")
            elif index == 1:
                if pwd_count > 0:
                    print("Password is wrong")
                    return 1
                else:
                    ssh.sendline(passwd)
                pwd_count += 1
        except pexpect.EOF:
            break
        except pexpect.TIMEOUT:
            break
    print("【run ssh cmd】" + ssh_cmd)
    return 0


def scp_to_remote(host, user, passwd, remote_path, local_path):
    """
    super scp use pexpect
    """
    remote_mk_dir_cmd = "sudo mkdir -p %s" % remote_path
    remote_cmd("%s@%s" % (user, host), passwd, remote_mk_dir_cmd)
    scp_cmd = 'scp -r ' + local_path + " " + user + "@" + host + ":" + remote_path
    ssh = pexpect.spawn('/bin/bash', ['-c', scp_cmd], timeout=1200)
    print("【run scp cmd】" + scp_cmd)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(['\(yes/no\)\?', 'assword:'])
            if not ssh.isalive() and index == 0:
                print("run ssh cmd success")
                return 0
            if index == 0:
                ssh.sendline("yes")
            elif index == 1:
                if pwd_count > 0:
                    print("Password is wrong")
                    return 1
                else:
                    ssh.sendline(passwd)
                    pwd_count += 1
        except pexpect.EOF:
            break
        except pexpect.TIMEOUT:
            break
    return 0


def get_from_remote(host, user, passwd, remote_path, local_path):
    """
    super scp use pexpect
    """
    cmd = "sudo mkdir -p %s && sudo chmod 777 %s" % (local_path, local_path)
    if run_cmd(cmd) is False:
        run_cmd("sudo mkdir -p %s" % local_path)

    if not os.path.exists(local_path):
        print("mkdir %s failed" % local_path)
        return -1

    scp_cmd = "scp -r %s@%s:%s %s" % (user, host, remote_path, local_path)
    print("【" + scp_cmd + "】")
    ssh = pexpect.spawn('/bin/bash', ['-c', scp_cmd], timeout=1200)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(['\(yes/no\)\?', 'assword:'])
            if not ssh.isalive() and index == 0:
                print("run ssh cmd success")
                return 0
            if index == 0:
                ssh.sendline("yes")
            elif index == 1:
                if pwd_count > 0:
                    print("Password is wrong")
                    return 1
                else:
                    ssh.sendline(passwd)
                    pwd_count += 1
        except pexpect.EOF:
            break
        except pexpect.TIMEOUT:
            break
    return 0


def run_cmd(cmd, timeout=1800):
    print("【cmd】" + cmd)
    end_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
    sub = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=True, bufsize=4096)

    while sub.poll() is None:
        time.sleep(5)
        if end_time <= datetime.datetime.now():
            raise Exception("Timeout：%s" % cmd)

    return True


def mkdir(path):
    cmd = "mkdir %s" % path
    run_cmd(cmd)


if __name__ == '__main__':
    remote_cmd("wangdongsheng@cq01-rdqa-dev007.cq01.baidu.com", "CAPHI2008", "ls; touch niubi")
