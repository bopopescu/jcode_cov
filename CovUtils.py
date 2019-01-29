#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import os
import sys
import stat
import errno
import shutil
import zipfile
import traceback
import subprocess
from pprint import pprint
from zipfile import ZipFile
from datetime import datetime
from qcs_env_coverage.venv import pexpect


def remote_cmd(remote, passwd, cmd):
    """
    Execute the command remotely
    :param remote:
    :param passwd:
    :param cmd:
    :return:
    """
    ssh_cmd = "ssh " + remote + " \"" + cmd + "\""
    ssh = pexpect.spawn("/bin/bash", ["-c", ssh_cmd], timeout=12)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(["\(yes/no\)\?", "assword:"])
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
    copy to remote by using ssh
    :param host:
    :param user:
    :param passwd:
    :param remote_path:
    :param local_path:
    :return:
    """
    remote_mk_dir_cmd = "sudo mkdir -p {}".format(remote_path)
    remote_cmd("{}@{}".format(user, host), passwd, remote_mk_dir_cmd)
    scp_cmd = "scp -rp " + local_path + " " + user + "@" + host + ":" + remote_path
    ssh = pexpect.spawn("/bin/bash", ["-c", scp_cmd], timeout=600)
    print("【Copying to remote】from {} to {}".format(local_path, remote_path))
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(["\(yes/no\)\?", "assword:"])
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
    copy from remote by using ssh
    :param host:
    :param user:
    :param passwd:
    :param remote_path:
    :param local_path:
    :return:
    """
    # This directory does not require super permissions
    cmd = "mkdir -p {} && chmod 777 {}".format(local_path, local_path)
    print("Create directory and set its permission with rwx.\n{}".format(local_path))
    if run_cmd(cmd) is False:
        run_cmd("mkdir -p {}".format(local_path))

    if not os.path.exists(local_path):
        print("Create {} failed.".format(local_path))
        return -1

    scp_cmd = "scp -rp {}@{}:{} {}".format(user, host, remote_path, local_path)
    print("Copying to local from {} to {}".format(remote_path, local_path))
    ssh = pexpect.spawn("/bin/bash", ["-c", scp_cmd], timeout=600)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(["\(yes/no\)\?", "assword:"])
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
    """
    Execute the command locally
    :param cmd:
    :param exception_on_errors:
    :return:
    """
    try:
        process = subprocess.Popen(cmd, shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as err:
        print("FAILED - run command: {}, {}".format(cmd, err))
        if exception_on_errors:
            raise Exception(err)

    print("Please waiting..")
    stdout, stderr = process.communicate()

    return_code = process.returncode
    if return_code != 0:
        err_msg = "FAILED - none zero exit code in {}".format(cmd)
        print("{}; stdout: {}; stderr: {}".format(err_msg, stdout, stderr))
        if exception_on_errors:
            raise Exception(err_msg)

    return True


def mkdir_p(path):
    """
    No error if existing, make parent directories as needed
    :param path:
    """
    try:
        os.makedirs(path)
    except OSError as exc:  # Python > 2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def handle_error(func, path, exc_info):
    """
    Handle the error that occurred and call back the handler function
    :param func:
    :param path:
    :param exc_info:
    """
    print("Handling Error for file ", path)
    print(exc_info)
    if not os.access(path, os.W_OK):
        print("Hello")
        os.chmod(path, stat.S_IWUSR)
        func(path)


def rmdir_rf(path):
    """
    Remove directories and their contents recursively
    :param path:
    """
    shutil.rmtree(path, onerror=handle_error)


def is_archive(filename):
    """
    Check file suffixes
    :param filename:
    :return:
    """
    ext = filename[-4:]

    if ext in [".war", ".jar"]:
        return True
    return False


def get_files_recursively(start_directory, filter_extension=None):
    """
    Collect specified file extension from source directory
    :param start_directory:
    :param filter_extension:
    """
    for root, _, files in os.walk(start_directory):
        for file in files:
            if filter_extension is None or file.lower().endswith(filter_extension):
                yield os.path.join(root, file)


def selective_copy(source, target, file_extension=None):
    """
    Copy source to target directory
    :param source:
    :param target:
    :param file_extension:
    """
    for file in get_files_recursively(source, file_extension):
        try:
            shutil.copy2(file, target)
        except shutil.Error:
            pass
        except IOError as e:
            print("IO Error: {}".format(e.strerror))


def extract_pack(pack, target_dir):
    """
    Extract the compressed packages into the specified directory
    :param pack:
    :param target_dir:
    """
    try:
        with ZipFile(pack, "r") as zf:
            zf.extractall(target_dir)
    except zipfile.BadZipFile as zb:
        print("BadZipFile: {}".format(zb))
    except zipfile.LargeZipFile as zl:
        print("LargeZipFile: {}".format(zl))
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        pprint(traceback.format_exception(exc_type, exc_value, exc_tb))


def time_now():
    """
    Get the local time dynamically
    :return time object
    """
    local_time_now = type("now", (), {"__repr__": lambda _: str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))})()
    return local_time_now
