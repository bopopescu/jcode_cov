#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import os
import sys
import stat
import errno
import shutil
import tarfile
import zipfile
import traceback
import subprocess
from zipfile import ZipFile
from datetime import datetime
from qcs_env_coverage.venv import pexpect
from qcs_env_coverage.CovLogger import CoverageLog

logger = CoverageLog.get_logger(os.path.basename(__file__))


def remote_cmd(remote, passwd, cmd):
    """
    Execute the command remotely
    :param remote:
    :param passwd:
    :param cmd:
    :return:
    """
    ssh_cmd = f'ssh {remote} "{cmd}"'
    ssh = pexpect.spawn("/bin/bash", ["-c", ssh_cmd], timeout=12)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(["\(yes/no\)\?", "assword:"])
            if not ssh.isalive() and index == 0:
                logger.info("run ssh cmd success")
                return 0
            if index == 0:
                ssh.sendline("yes")
            elif index == 1:
                if pwd_count > 0:
                    logger.error("Password is wrong")
                    return 1
                else:
                    ssh.sendline(passwd)
                pwd_count += 1
        except pexpect.EOF:
            break
        except pexpect.TIMEOUT:
            break
    logger.info(f"【run ssh cmd】{ssh_cmd}")
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
    remote_mk_dir_cmd = f"sudo mkdir -p {remote_path}"
    remote_cmd(f"{user}@{host}", passwd, remote_mk_dir_cmd)
    logger.info(f"Copying to remote from {local_path} to {remote_path}")
    scp_cmd = f"scp -rp {local_path} {user}@{host}:{remote_path}"
    ssh = pexpect.spawn("/bin/bash", ["-c", scp_cmd], timeout=600)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(["\(yes/no\)\?", "assword:"])
            if not ssh.isalive() and index == 0:
                logger.info("run ssh cmd success")
                return 0
            if index == 0:
                ssh.sendline("yes")
            elif index == 1:
                if pwd_count > 0:
                    logger.error("Password is wrong")
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
    logger.info("Create local directory and set its permission with rwx.")
    cmd = f"mkdir -p {local_path} && chmod 777 {local_path}"
    if run_cmd(cmd) is False:
        run_cmd(f"mkdir -p {local_path}")

    if not os.path.exists(local_path):
        logger.error(f"FAILED - create {local_path}.")
        return -1

    logger.info(f"Copying to local from {remote_path} to {local_path}")
    scp_cmd = f"scp -rp {user}@{host}:{remote_path} {local_path}"
    ssh = pexpect.spawn("/bin/bash", ["-c", scp_cmd], timeout=600)
    pwd_count = 0
    while 1:
        try:
            index = ssh.expect(["\(yes/no\)\?", "assword:"])
            if not ssh.isalive() and index == 0:
                logger.info("run ssh cmd success")
                return 0
            if index == 0:
                ssh.sendline("yes")
            elif index == 1:
                if pwd_count > 0:
                    logger.error("password is wrong")
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
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, encoding="utf-8")
    except Exception as err:
        logger.error(f"FAILED - run command: {cmd}, {err}")
        if exception_on_errors:
            raise Exception(err)

    logger.debug("Please waiting..")
    stdout, stderr = process.communicate()

    return_code = process.returncode
    if return_code != 0:
        err_msg = f"FAILED - none zero exit code in {cmd}"
        logger.error(f"{err_msg}; stdout: {stdout}; stderr: {stderr}")
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
    logger.info(f"Handling Error for file {path}")
    logger.info(exc_info)
    if not os.access(path, os.W_OK):
        logger.info(f"Re-handle {path}")
        os.chmod(path, stat.S_IWUSR)
        func(path)


def rmdir_rf(path):
    """
    Remove directories and their contents recursively
    :param path:
    """
    shutil.rmtree(path, onerror=handle_error)


def is_archive(file_path):
    """
    Check file extension
    :param file_path:
    :return:
    """
    fn, ext = os.path.splitext(file_path)
    if ext in [".zip", ".jar", ".war", ".tar", ".gz", ".tgz"]:
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
            logger.error(f"IO Error: {e.strerror}")


def extract_pack(pack_name, target_dir):
    """
    Extract the compressed packages into the specified directory
    :param pack_name: filename
    :param target_dir: extract directory
    """
    fn, ext = os.path.splitext(pack_name)

    if ext in [".zip", ".jar", ".war"]:
        with zipfile.ZipFile(pack_name, "r") as zf:
            zf.extractall(target_dir)
    elif ext in ".tar":
        with tarfile.TarFile(pack_name, "r") as tf:
            tf.extractall(target_dir)
    elif ext in [".gz", ".tgz"]:
        with tarfile.open(pack_name, "r:gz") as tf:
            tf.extractall(target_dir)


def _extract_pack(pack, target_dir):
    """
    Extract the compressed packages into the specified directory
    :param pack:
    :param target_dir:
    """
    try:
        with ZipFile(pack, "r") as zf:
            zf.extractall(target_dir)
    except zipfile.BadZipFile as zb:
        logger.error(f"BadZipFile: {zb}")
    except zipfile.LargeZipFile as zl:
        logger.error(f"LargeZipFile: {zl}")
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        logger.error(traceback.format_exception(exc_type, exc_value, exc_tb))


def path_join(*args):
    """
    Join two or more pathname components
    :param args:
    :return:
    """
    return os.path.join(*args)


def time_now_dyna():
    """
    Get the local time dynamically
    :return time object
    """
    local_time_now = type("now", (), {"__repr__": lambda _: str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))})()
    return local_time_now


def time_now_stat():
    """
    Get the local time statically
    :return time object
    """
    local_time_now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
    return local_time_now
