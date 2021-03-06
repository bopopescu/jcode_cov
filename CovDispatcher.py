#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import os
import sys
import math
import json
import time
import argparse

current_path = os.path.abspath(os.path.dirname(__file__))
root_path = os.path.abspath(os.path.join(current_path, ".."))
sys.path.insert(0, root_path)
sys.path.insert(0, os.path.join(root_path, "venv"))

from qcs_env_coverage.CovUtils import *
from qcs_env_coverage.venv import requests
from qcs_env_coverage.venv import xmltodict
from qcs_env_coverage.CovLogger import CoverageLog
from qcs_env_coverage.CovPlusInfo import PlusRecord

logger = CoverageLog.get_logger(os.path.basename(__file__))


class CoverageDispatcher(object):
    def __init__(self, plus_name, template_name, host_ip, branch, git_url=None):
        self.coverage_info = {}
        self.p_record = PlusRecord(plus_name, template_name, host_ip, branch, git_url)
        self.service_server_username = "sk"
        self.service_server_userhome = path_join("/home", self.service_server_username)
        self.file_server_hostname = "YmJeal5iaGxfaGk="
        self.file_server_passwd = "lqKkpZ-cqGljYw=="
        self.local_output_path = path_join(current_path, "output")
        self.remote_dump_jar_path = path_join(current_path, "venv", "qcs-env-coverage-remote-dump.jar")
        self.line_coverage_jar_path = path_join(current_path, "venv", "qcs-env-line-coverage.jar")

    def clean(self, port):
        """
        push to remote server and execute remote command,
        jenkins salve cannot clear the server coverage data remotely.
        :param port:
        """
        scp_to_remote(self.p_record.host, self.service_server_username, "",
                      self.service_server_userhome + os.sep, self.remote_dump_jar_path)

        _remote_dump_jar_path = path_join(self.service_server_userhome, "qcs-env-coverage-remote-dump.jar")
        run_jar_cmd = f"java -jar {_remote_dump_jar_path} {self.p_record.host} {port} clean"
        remote_cmd(f"{self.service_server_username}@{self.p_record.host}", "", run_jar_cmd)

    def dump(self, remote_class_path, port, jobname, old_commit, new_commit, old_branch, job_url):
        """
        dump coverage data
        :param remote_class_path:
        :param port:
        :param jobname:
        :param old_commit:
        :param new_commit:
        :param old_branch:
        :param job_url:
        """
        mkdir_p(self.local_output_path)

        local_time = time_now_st()

        exec_name_s = f"{self.p_record.plus_name}_{local_time}_jacoco.exec"
        exec_name_f = path_join(self.local_output_path, exec_name_s)
        run_jar_cmd = f"java -jar {self.remote_dump_jar_path} {self.p_record.host} {port} dump {exec_name_f}"
        run_cmd(run_jar_cmd)

        self.coverage_info["exec"] = exec_name_f

        local_class_path = path_join(self.local_output_path,
                                     f"webroot_{self.p_record.plus_name}_{local_time}")
        if not self.get_remote_class(remote_class_path, local_class_path):
            raise SystemExit

        local_src_path = path_join(self.local_output_path, f"src_{self.p_record.plus_name}_{local_time}")
        # comment it out temporarily for qcs auto cov
        # jobname = os.path.abspath(path_join(os.path.dirname(__file__), os.pardir, os.pardir)).split("/")[-1]

        self.get_git_code(local_src_path, old_commit, new_commit, old_branch, jobname, job_url)

        # comment it out temporarily for qcs auto cov
        # self.scp_output_to_remote(local_time, jobname)

    def get_remote_class(self, remote_class_path, local_class_path):
        """
        fetch remote service class
        :param remote_class_path:
        :param local_class_path:
        """
        logger.info("Extract test service classes.")
        local_coverage_class_path = path_join(local_class_path, "coverage_classes")
        local_temp_coverage_class_path = path_join(local_class_path, "temp_classes")
        mkdir_p(local_coverage_class_path)

        get_from_remote(self.p_record.host, self.service_server_username, "", remote_class_path, local_class_path)
        selective_copy(local_class_path, local_coverage_class_path, ".class")

        if remote_class_path.endswith("/"):
            service_dir = remote_class_path.split("/")[-2]
        else:
            service_dir = remote_class_path.split("/")[-1]
        local_service_dir = path_join(local_class_path, service_dir)
        try:
            path_list = os.listdir(local_service_dir)
        except OSError:
            logger.error(f"Service deploy directory {remote_class_path} failed.")
            return False
        for item in path_list:
            if is_archive(item):
                mkdir_p(local_temp_coverage_class_path)
                pack_name = path_join(local_service_dir, item)
                extract_pack(pack_name, local_temp_coverage_class_path)
                selective_copy(local_temp_coverage_class_path, local_coverage_class_path, ".class")
                rmdir_rf(local_temp_coverage_class_path)

        # Clean temp service directory
        rmdir_rf(local_service_dir)
        self.coverage_info["class"] = local_class_path
        return True

    def get_git_code(self, local_src_path, old_commit, new_commit, old_branch, jobname, job_url):
        """
        fetch service source code
        :param local_src_path:
        :param old_commit:
        :param new_commit:
        :param old_branch:
        :param jobname:
        :param job_url:
        :return:
        """
        logger.info(f"Clone source code to {local_src_path}")
        mkdir_p(local_src_path)
        src_space = local_src_path + os.sep + self.p_record.git.split("/")[-1].rsplit(".", 1)[0]

        cmd = f"cd {local_src_path} && git clone {self.p_record.git} && cd {src_space} && "

        commit_hash_len = 10
        if self.p_record.git_url is None and self.p_record.commit is not None \
                and len(self.p_record.commit) > commit_hash_len:
            cmd += f"git checkout {self.p_record.commit}"
        else:
            cmd += f"git checkout {self.p_record.branch}"

        self.coverage_info["src"] = local_src_path

        run_cmd(cmd)
        if len(os.listdir(src_space)) < 1:
            logger.error("Git fetch failed.")
            return

        self.get_diff_cov(old_commit, new_commit, src_space, old_branch, jobname, job_url)

    def get_diff_cov(self, old_commit, new_commit, src_space, old_branch, jobname, job_url):
        """
        fetch git diff coverage
        :param old_commit:
        :param new_commit:
        :param src_space:
        :param old_branch:
        :param jobname:
        :param job_url:
        :return:
        """
        if old_branch is not None:
            logger.info(f"Fill in --old-branch, get {old_branch} & {self.p_record.branch} branch diff")
            old_commit = old_branch
            new_commit = self.p_record.branch
            cmd = f"cd {src_space} && git checkout {old_commit} && git checkout {new_commit}"
            run_cmd(cmd)
        else:
            if old_commit is None:
                logger.info("Did not fill in --old-commit for src code, git increments could not be obtained.")
                return

            if new_commit is None:
                cmd = f"cd {src_space} && git log > git.log"
                run_cmd(cmd)

                src_space_git_log = path_join(src_space, "git.log")
                new_commit = self.get_new_commit(src_space_git_log)
                run_cmd(f"rm -rf {src_space_git_log}")
                if new_commit is None:
                    logger.error("Did not fill in --new-commit for src code, git log does not get the latest commit.")
                    return

        cmd = f"cd {src_space} && git diff {old_commit} {new_commit} > diff.txt"
        run_cmd(cmd)

        excludes = self.get_jenkins_exclusion_pattern(jobname, job_url)

        run_jar_cmd = f"java -Dfile.encoding=utf-8 -jar {self.line_coverage_jar_path} " \
            f"{path_join(src_space, 'diff.txt')} {self.p_record.plus_name} {excludes}"
        run_cmd(run_jar_cmd)

        if os.path.isfile(path_join(src_space, "diffcov.txt")):
            if not os.path.exists(path_join(self.local_output_path, "diff2html")):
                cmd = f"cp -rp {path_join(root_path, 'venv', 'diff2html')} {self.local_output_path}"
                run_cmd(cmd)
            self.store_to_report_dir(self.local_output_path, src_space)
            source_diffcov_html = path_join(root_path, "venv", "diffcov.html")
            target_diffcov_html = path_join(self.local_output_path, "diff2html", self.p_record.plus_name + ".html")

            self.get_diff_cov_to_html(path_join(src_space, "diffcov.txt"), source_diffcov_html, target_diffcov_html)

    def store_to_report_dir(self, output_path, src_space):
        """
        :param output_path:
        :param src_space:
        """
        diff2html_dir = path_join(output_path, "diff2html")
        cmd = f"cp -rp {path_join(output_path, 'webroot_*')} {diff2html_dir}"
        run_cmd(cmd)
        cmd = f"cp -rp {path_join(output_path, '*.exec')} {diff2html_dir}"
        run_cmd(cmd)
        cmd = f"cp -rp {path_join(src_space, 'diff.txt')} {diff2html_dir}"
        run_cmd(cmd)
        cmd = f"cp -rp {path_join(src_space, 'diffcov.txt')} {diff2html_dir}"
        run_cmd(cmd)

    def get_new_commit(self, log_path):
        """
        :param log_path:
        :return:
        """
        with open(log_path, "r") as fr:
            line = fr.readline()

        if "commit" in line:
            return line.split(" ")[1].replace("\n", "")
        return None

    def get_jenkins_exclusion_pattern(self, jobname, job_url):
        """
        :param jobname:
        :param job_url:
        :return:
        """
        # url = get_jenkins_url_by_jobname(jobname)
        url = job_url
        logger.info(url)

        if url is None:
            return ""

        return self.get_jenkins_config(f"{url}/config.xml")

    def get_jenkins_config(self, url):
        """
        :param url:
        :return:
        """
        response = send_request(url)
        if response is None:
            return ""
        try:
            converted_dict = xmltodict.parse(response)
            json_config = json.loads(json.dumps(converted_dict))
        except:
            return ""

        path_list = ["project", "publishers", "hudson.plugins.jacoco.JacocoPublisher", "exclusionPattern"]
        config_value = self.get_config_value(path_list, json_config)

        if config_value is None or len(config_value) == 0:
            path_list = ["maven2-moduleset", "publishers", "hudson.plugins.jacoco.JacocoPublisher", "exclusionPattern"]
            config_value = self.get_config_value(path_list, json_config)

        return config_value

    def get_config_value(self, path_list, value):
        """
        :param path_list:
        :param value:
        :return:
        """
        for path in path_list:
            if value is None:
                return ""

            if path in value:
                value = value[path]
            else:
                return ""
        if value is None:
            return ""
        return value.replace(" ", "")

    def get_diff_cov_to_single_html(self, source_path, target_path, outfile, content):
        """
        :param source_path:
        :param target_path:
        :param outfile:
        :param content:
        """
        infile = f"{source_path}/diffcov_subpage.html"
        with open(infile, "r") as fr, open(outfile, "w+") as fw:
            html = fr.read()
            html = html.replace("$lineDiffLog", content)
            fw.write(html)

    def get_diff_cov_to_html(self, diffcov_txt, source_diffcov_html, target_diffcov_html):
        """
        :param diffcov_txt:
        :param source_diffcov_html:
        :param target_diffcov_html:
        """
        target_path = target_diffcov_html[:target_diffcov_html.rfind("/")]
        source_path = source_diffcov_html[:source_diffcov_html.rfind("/")]
        with open(diffcov_txt, "r") as fr:
            lines = fr.readlines()

        cov_lines = 0
        mis_lines = 0
        line_diff_cov = ""
        flag_newfile = 1
        src_name = ""
        file_no = -1
        diff_file_list = ""
        diff_filename = ""
        for line in lines:
            if file_no >= 0 and line.find("diff") == 0:
                src_html_name = target_path + "/" + str(file_no) + ".html"

                diff_file_list += "<tr><td class=\"" + "spikeDataTableCellLeft\"> <a  class=\"" + \
                                  "contentlink\" href=\"" + str(file_no) + ".html\" title=\"" + \
                                  diff_filename + "\">" + diff_filename + "</a></td></tr>"
                self.get_diff_cov_to_single_html(source_path, target_path, src_html_name, line_diff_cov[1:])
                line_diff_cov = ""
            if line.find("diff") == 0:
                file_no = file_no + 1
                diff_filename = line[line.find("b/") + 1:]
            if line.endswith("\n"):
                line = line[:-1]

            if (line.startswith("+") and not line.startswith("++")) or line.startswith("P+"):
                cov_lines += 1
            if line.startswith("M+"):
                mis_lines += 1

            line = line.replace("\\'", "\\\\'")
            line = line.replace("'", "\\'")
            line = line.replace("\\n", "\\\\n")
            line_diff_cov += "+'" + line + "\\n'\n"

        if file_no >= 0:
            src_html_name = target_path + os.sep + str(file_no) + ".html"
            diff_file_list += "<tr><td class=\"" + "spikeDataTableCellLeft\"> <a class=\"" + \
                              "contentlink\" href=\"" + str(file_no) + ".html\" title=\"" + \
                              diff_filename + "\">" + diff_filename + "</a></td></tr>"
            self.get_diff_cov_to_single_html(source_path, target_path, src_html_name, line_diff_cov[1:])

        infile = f"{source_path}/diffcov.html"
        with open(infile, "r") as fr:
            html = fr.read()

        if cov_lines + mis_lines == 0:
            diff_cov_rate = 0
        else:
            diff_cov_rate = int(math.ceil(cov_lines * 100.0 / (cov_lines + mis_lines)))
        html = html.replace("$diffCovRate", str(diff_cov_rate))
        html = html.replace("$diffMissRate", str(100 - diff_cov_rate))
        html = html.replace("$missLines", str(mis_lines))
        html = html.replace("$covLines", str(cov_lines))
        html = html.replace("$fileList", str(diff_file_list))

        with open(target_diffcov_html, "w+") as fw:
            fw.write(html)

    def scp_output_to_remote(self, date_path, jobname):
        """
        push output to remote server
        :param date_path:
        :param jobname:
        """
        logger.info("Put output to remote.")
        list_dir = os.listdir(self.local_output_path)
        if len(os.listdir(self.local_output_path)) < 1:
            logger.error(f"Please check {self.local_output_path}")
            return

        jacoco_flag = False
        class_flag = False
        for item in list_dir:
            if item.endswith("_jacoco.exec"):
                jacoco_flag = True
            if item.endswith("_class") or item.startswith("webroot_"):
                class_flag = True

        if jacoco_flag and class_flag:
            file_server_root = path_join(self.service_server_userhome, "jacocoReports")
            job_path = path_join(file_server_root, jobname)
            date_path = path_join(job_path, date_path)
            r_user = "root"

            cmd = f"sudo mkdir -p {job_path} && sudo chmod 777 {job_path}"
            remote_cmd(f"{r_user}@{self.file_server_hostname}", self.file_server_passwd, cmd)

            cmd = f"sudo mkdir -p {date_path} && sudo chmod 777 {date_path}"
            remote_cmd(f"{r_user}@{self.file_server_hostname}", self.file_server_passwd, cmd)

            scp_to_remote(self.file_server_hostname, r_user, self.file_server_passwd,
                          date_path, self.local_output_path)
        else:
            logger.error("lack jacoco.exec and classes")

    def dump_git_info(self):
        """
        dump coverage to data file
        """
        with open("coverage.json", "a") as fd:
            fd.write(json.dumps(self.coverage_info))
            fd.write("\n")


def send_request(url):
    authorization = "Basic Y2kuc2Fua3VhaTpQUDg1MTAxOGpK"

    try_count = 0
    response = None
    while try_count < 5:
        try:
            response = requests.get(url, headers={"Authorization": authorization})
        except Exception as e:
            logger.error(e)
            logger.error("requests.exceptions.ConnectionError try again")
            try_count += 1
            time.sleep(2)
            continue
        break

    if response is not None and response.status_code == 200:
        try:
            return json.loads(response.text)
        except:
            return response.text
    logger.error(f"jenkins job {url} error, or requests.exceptions.ConnectionError.")
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--plusname", default=None, type=str, help="plus发布项")
    parser.add_argument("-t", "--template", default=None, type=str, help="模板类型")
    parser.add_argument("-a", "--action", default=None, type=str, help="执行类型")
    parser.add_argument("-p", "--port", default=None, type=str, help="jacocoagent port")
    parser.add_argument("-c", "--classes", default=None, type=str, help="class路径")
    parser.add_argument("-j", "--jobname", default=None, type=str, help="jenkins job name")
    parser.add_argument("-i", "--host_ip", default=None, type=str, help="被测服务ip")
    parser.add_argument("-b", "--branch", default=None, type=str, help="代码branch")
    parser.add_argument("-u", "--job_url", default=None, type=str, help="统计覆盖率job的地址")
    parser.add_argument("-g", "--git_url", default=None, type=str, help="git仓库地址")
    parser.add_argument("--old-commit", "--old_commit", default=None, type=str, help="git源代码老版本")
    parser.add_argument("--new-commit", "--new_commit", default=None, type=str, help="git源代码新版本")
    parser.add_argument("--old-branch", "--old_branch", default=None, type=str, help="git源代码老分支")

    args = parser.parse_args()

    plus_name = args.plusname
    template_name = args.template
    action = args.action
    port = args.port
    host_ip = args.host_ip
    branch = args.branch
    git_url = args.git_url

    logger.info(args)
    if plus_name is None:
        logger.error("未填写-n plusname发布项参数")
        return

    if host_ip is None:
        logger.error("未填写-h 被测服务ip")
        return

    if template_name is None:
        logger.info("未填写模板类型，默认为test模板")
        template_name = "test"

    if port is None:
        logger.info("未填写port，默认为6300")
        port = "6300"

    if branch is None:
        logger.info("未填写代码branch，默认为master")
        branch = "master"

    if git_url:
        coverage_master = CoverageDispatcher(plus_name, template_name, host_ip, branch, git_url)
    else:
        coverage_master = CoverageDispatcher(plus_name, template_name, host_ip, branch)

        if not coverage_master.p_record.flag:
            logger.error("获取plus配置失败")
            return

    if action == "clean":
        logger.info("clean操作：开始清理覆盖率数据")
        coverage_master.clean(port)

    elif action == "dump":
        logger.info("dump操作：开始dump远程覆盖率数据")
        jobname = args.jobname
        classes = args.classes

        if classes is None:
            logger.error("dump操作未填写-c classes参数")
            return

        coverage_master.dump(classes, port, jobname, args.old_commit, args.new_commit, args.old_branch,
                             args.job_url)


if __name__ == "__main__":
    main()
