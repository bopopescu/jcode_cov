#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import os
import subprocess
from qcs_env_coverage.thirdparts import pexpect


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
    # This directory does not require super permissions
    cmd = "mkdir -p %s && chmod 777 %s" % (local_path, local_path)
    if run_cmd(cmd) is False:
        run_cmd("mkdir -p %s" % local_path)

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


def run_cmd(cmd, exception_on_errors=True):
    try:
        print("【cmd】" + cmd)
        process = subprocess.Popen(cmd, shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as err:
        print('FAILED - run command: %s, %s' % (cmd, err))
        if exception_on_errors:
            raise Exception(err)

    print('Please waiting..')
    stdout, stderr = process.communicate()

    return_code = process.returncode
    if return_code != 0:
        err_msg = 'FAILED - none zero exit code in %s' % cmd
        print('%s; stdout: %s; stderr: %s' % (err_msg, stdout, stderr))
        if exception_on_errors:
            raise Exception(err_msg)

    return True


def mkdir(path):
    cmd = "mkdir %s" % path
    run_cmd(cmd)
