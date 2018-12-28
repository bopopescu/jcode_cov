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
proj_path = os.path.abspath(os.path.join(current_path, "../.."))
root_path = os.path.abspath(os.path.join(current_path, ".."))
sys.path.insert(0, proj_path)

from qcs_env_coverage.lib.CovUtils import *
from qcs_env_coverage.lib.CovLogger import CovLog
from qcs_env_coverage.lib.PlusInfo import PlusRecord
from qcs_env_coverage.thirdparts import requests
from qcs_env_coverage.thirdparts import xmltodict

clog = CovLog()


class CoverageMaster(object):
    def __init__(self, plus_name, template_name, host_ip, branch, git_url=None):
        self.p_record = PlusRecord(plus_name, template_name, host_ip, branch, git_url)
        self.file_server_hostname = "10.4.236.69"
        self.file_server_passwd = "eptools321"
        self.local_output_path = os.path.join(root_path, 'output')
        self.remote_dump_jar_path = os.path.join(root_path, "thirdparts/architect-coverage-remote-dump.jar")
        self.line_coverage_jar_path = os.path.join(root_path, "thirdparts/architect-line-coverage.jar")
        self.coverage_info = {}

    def clean(self, port):
        """
        push to remote server and execute remote command,
        jenkins salve cannot clear the server coverage data remotely.
        :param port:
        """
        scp_to_remote(self.p_record.host, 'sankuai', "", "/home/sankuai/",
                      self.remote_dump_jar_path)

        clog.info("args[0]=ip, arg[1]=port, arg[2]=action")

        run_jar_cmd = "java -jar /home/sankuai/architect-coverage-remote-dump.jar {} {} clean".format(
            self.p_record.host, port)
        remote_cmd("sankuai@{0}".format(self.p_record.host), "", run_jar_cmd)

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
        clog.info("args[0]=ip, arg[1]=port, arg[2]=action, arg[3]=exec path")

        mkdir(self.local_output_path)

        local_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())

        exec_name = os.path.join(self.local_output_path, self.p_record.plus_name + local_time + "_jacoco.exec")
        run_jar_cmd = "java -jar {} {} {} dump {}".format(
            self.remote_dump_jar_path, self.p_record.host, port, exec_name)
        run_cmd(run_jar_cmd)

        self.coverage_info['exec'] = exec_name

        local_class_path = os.path.join(self.local_output_path,
                                        "webroot_{}{}".format(self.p_record.plus_name, local_time))
        self.get_remote_class(remote_class_path, local_class_path)

        local_src_path = os.path.join(self.local_output_path, "src_{}{}".format(self.p_record.plus_name, local_time))
        # comment it out temporarily for qcs auto cov
        # jobname = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)).split('/')[-1]

        self.get_git_code(local_src_path, old_commit, new_commit, old_branch, jobname, job_url)

        # comment it out temporarily for qcs auto cov
        # self.scp_output_to_remote(local_time, jobname)

    def get_remote_class(self, remote_class_path, local_class_path):
        """
        fetch remote service class
        :param remote_class_path:
        :param local_class_path:
        """
        clog.info("get tested service classes")
        mkdir(local_class_path)

        remote_class_path_list = remote_class_path.split(",")

        for item in remote_class_path_list:
            if ".war" in item:
                index = item.find(".war") + len(".war")
                tmp = item[:index]
                cmd = "unzip {} -d {}".format(tmp, tmp.replace(".war", ""))
                remote_cmd("sankuai@{0}".format(self.p_record.host), "", cmd)
                item = item.replace(".war", "")

            get_from_remote(self.p_record.host, 'sankuai', '', item, local_class_path)

        path_list = os.listdir(local_class_path)
        for item in path_list:
            if item.endswith(".jar"):
                tmp_classes = os.path.join(local_class_path, item.replace(".jar", ""))
                mkdir(tmp_classes)
                tmp_classes += "/classes"
                mkdir(tmp_classes)

                run_cmd("mv {} {}".format(os.path.join(local_class_path, item), tmp_classes))

                jar_path = os.path.join(tmp_classes, item)
                run_cmd("unzip -d {} {}".format(tmp_classes, jar_path))
                run_cmd("rm -rf {}".format(jar_path))

        self.coverage_info['class'] = local_class_path

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

        clog.info("clone rd code to jenkins slave")
        mkdir(local_src_path)
        src_space = local_src_path + os.sep + self.p_record.git.split('/')[-1].rsplit('.', 1)[0]

        cmd = "cd {} && git clone {} && cd {} && ".format(local_src_path, self.p_record.git, src_space)

        commit_hash_len = 10
        if self.p_record.commit is not None and len(self.p_record.commit) > commit_hash_len:
            cmd += "git checkout {}".format(self.p_record.commit)
        else:
            cmd += "git checkout {}".format(self.p_record.branch)

        self.coverage_info['src'] = local_src_path

        print(cmd)
        run_cmd(cmd)
        if len(os.listdir(src_space)) < 1:
            clog.error("Git fetch failed.")
            return

        self.get_diff_cov(old_commit, new_commit, src_space, old_branch, jobname, job_url)

    def get_diff_cov(self, old_commit, new_commit, src_space, old_branch, jobname, job_url):
        """ fetch git diff coverage
        :param old_commit:
        :param new_commit:
        :param src_space:
        :param old_branch:
        :param jobname:
        :param job_url:
        :return:
        """

        if old_branch is not None:
            clog.info("Fill in --old-branch, get {} & {} branch diff".format(old_branch, self.p_record.branch))
            old_commit = old_branch
            new_commit = self.p_record.branch
            cmd = "cd {} && git checkout {} && git checkout {}".format(src_space, old_commit, new_commit)
            run_cmd(cmd)
        else:
            if old_commit is None:
                clog.info("Did not fill in --old-commit git old version parameters "
                          "for source code，Git increments could not be obtained.")
                return

            if new_commit is None:
                cmd = "cd {} && git log > git.log".format(src_space)
                run_cmd(cmd)

                new_commit = self.get_new_commit(src_space + "/git.log")
                run_cmd("rm -rf {}/git.log".format(src_space))
                if new_commit is None:
                    clog.error("Did not fill in --new-commit git new version parameter "
                               "and git log does not get the latest commit.")
                    return

        cmd = "cd {} && git diff {} {} > diff.txt".format(src_space, old_commit, new_commit)
        run_cmd(cmd)

        excludes = self.get_jenkins_exclusion_pattern(jobname, job_url)

        run_jar_cmd = "java -Dfile.encoding=utf-8 -jar {} {} {} {}".format(
            self.line_coverage_jar_path, src_space + "/diff.txt", self.p_record.plus_name, excludes)
        run_cmd(run_jar_cmd)

        if os.path.isfile(src_space + "/diffcov.txt"):
            if not os.path.exists(self.local_output_path + "/diff2html"):
                cmd = "cp -r {} {}".format(os.path.join(root_path, "thirdparts/diff2html"), self.local_output_path)
                run_cmd(cmd)
            self.store_to_report_dir(self.local_output_path, src_space)
            source_diffcov_html = os.path.join(root_path, "thirdparts/diffcov.html")
            target_diffcov_html = self.local_output_path + "/diff2html/" + self.p_record.plus_name + ".html"

            self.get_diff_cov_to_html(src_space + "/diffcov.txt", source_diffcov_html, target_diffcov_html)

    def store_to_report_dir(self, output_path, src_space):
        """
        :param output_path:
        :param src_space:
        """
        cmd = "cp -r {} {}".format(os.path.join(output_path, "webroot_*"), output_path + "/diff2html")
        run_cmd(cmd)
        cmd = "cp {} {}".format(os.path.join(output_path, "*.exec"), output_path + "/diff2html")
        run_cmd(cmd)
        cmd = "cp {} {}".format(os.path.join(src_space, "diff.txt"), output_path + "/diff2html")
        run_cmd(cmd)
        cmd = "cp {} {}".format(os.path.join(src_space, "diffcov.txt"), output_path + "/diff2html")
        run_cmd(cmd)

    def get_new_commit(self, log_path):
        """
        :param log_path:
        :return:
        """
        fr = open(log_path, "r")
        line = fr.readline()
        fr.close()
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
        clog.info(url)

        if url is None:
            return ""

        return self.get_jenkins_config(url + "/config.xml")

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

        path_list = ['project', 'publishers', 'hudson.plugins.jacoco.JacocoPublisher', 'exclusionPattern']
        config_value = self.get_config_value(path_list, json_config)

        if config_value is None or len(config_value) == 0:
            path_list = ['maven2-moduleset', 'publishers', 'hudson.plugins.jacoco.JacocoPublisher', 'exclusionPattern']
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

    def get_diff_cov_to_single_html(self, source_path, target_path, filename, content):
        """
        :param source_path:
        :param target_path:
        :param filename:
        :param content:
        """
        fr = open(source_path + "/diffcov_subpage.html", "r")
        html = fr.read()
        fr.close()
        html = html.replace("$lineDiffLog", content)
        fw = open(filename, "w+")
        fw.write(html)
        fw.close()

    def get_diff_cov_to_html(self, diffcov_txt, source_diffcov_html, target_diffcov_html):
        """
        :param diffcov_txt:
        :param source_diffcov_html:
        :param target_diffcov_html:
        """
        target_path = target_diffcov_html[:target_diffcov_html.rfind("/")]
        source_path = source_diffcov_html[:source_diffcov_html.rfind("/")]
        fr = open(diffcov_txt, "r")
        lines = fr.readlines()
        fr.close()

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
            src_html_name = target_path + "/" + str(file_no) + ".html"
            diff_file_list += "<tr><td class=\"" + "spikeDataTableCellLeft\"> <a class=\"" + \
                              "contentlink\" href=\"" + str(file_no) + ".html\" title=\"" + \
                              diff_filename + "\">" + diff_filename + "</a></td></tr>"
            self.get_diff_cov_to_single_html(source_path, target_path, src_html_name, line_diff_cov[1:])

        fr = open(source_path + "/diffcov.html", "r")
        html = fr.read()
        fr.close()

        if cov_lines + mis_lines == 0:
            diff_cov_rate = 0
        else:
            diff_cov_rate = int(math.ceil(cov_lines * 100.0 / (cov_lines + mis_lines)))
        html = html.replace("$diffCovRate", str(diff_cov_rate))
        html = html.replace("$diffMissRate", str(100 - diff_cov_rate))
        html = html.replace("$missLines", str(mis_lines))
        html = html.replace("$covLines", str(cov_lines))
        html = html.replace("$fileList", str(diff_file_list))

        fw = open(target_diffcov_html, "w+")
        fw.write(html)
        fw.close()

    def scp_output_to_remote(self, date_path, jobname):
        """
        push output to remote server
        :param date_path:
        :param jobname:
        """
        clog.info("output to remote")
        list_dir = os.listdir(self.local_output_path)
        jacoco_flag = False
        class_flag = False
        for item in list_dir:
            if item.endswith("_jacoco.exec"):
                jacoco_flag = True
            if item.endswith("_class") or item.startswith("webroot_"):
                class_flag = True

        if jacoco_flag and class_flag:
            file_server_root = "/home/sankuai/jacocoReports"
            job_path = os.path.join(file_server_root, jobname)
            date_path = os.path.join(job_path, date_path)

            cmd = "sudo mkdir {} && sudo chmod 777 {}".format(job_path, job_path)
            remote_cmd("root@{0}".format(self.file_server_hostname), self.file_server_passwd, cmd)

            cmd = "sudo mkdir {} && sudo chmod 777 {}".format(date_path, date_path)
            remote_cmd("root@{0}".format(self.file_server_hostname), self.file_server_passwd, cmd)

            scp_to_remote(self.file_server_hostname, "root", self.file_server_passwd,
                          date_path, self.local_output_path)
        else:
            clog.error("lack jacoco.exec and classes")

    def dump_git_info(self):
        """
        dump coverage to data file
        """
        fd = open('coverage.json', 'a')
        fd.write(json.dumps(self.coverage_info))
        fd.write('\n')
        fd.close()


def send_request(url):
    authorization = "Basic Y2kuc2Fua3VhaTpQUDg1MTAxOGpK"

    try_count = 0
    response = None
    while try_count < 5:
        try:
            response = requests.get(url, headers={"Authorization": authorization})
        except Exception as e:
            print(e)
            clog.error("requests.exceptions.ConnectionError try again")
            try_count += 1
            time.sleep(2)
            continue
        break

    if response is not None and response.status_code == 200:
        try:
            return json.loads(response.text)
        except:
            return response.text
    clog.info("jenkins job {} error, or requests.exceptions.ConnectionError ".format(url))
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
    # 注意: 当plusname设置成appkey的name时候,git_url才需要指定, 因为如果不指定无法获取源码
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

    clog.info("命令行参数:" + str(args))
    if plus_name is None:
        clog.error("未填写-n plusname发布项参数")
        return

    if host_ip is None:
        clog.error("未填写-h 被测服务ip")
        return

    if template_name is None:
        clog.info("未填写模板类型，默认为test模板")
        template_name = "test"

    if port is None:
        clog.info("未填写port，默认为6300")
        port = "6300"

    if branch is None:
        clog.info("未填写代码branch，默认为master")
        branch = "master"

    if git_url is not None:
        coverage_master = CoverageMaster(plus_name, template_name, host_ip, branch, git_url)
    else:
        coverage_master = CoverageMaster(plus_name, template_name, host_ip, branch)

        if not coverage_master.p_record.flag:
            clog.error("获取plus配置失败")
            return

    if action == 'clean':
        clog.info("clean操作：开始清理覆盖率数据")
        coverage_master.clean(port)

    elif action == 'dump':
        clog.info("dump操作：开始dump远程覆盖率数据")
        jobname = args.jobname
        classes = args.classes

        if classes is None:
            clog.error("dump操作未填写-c classes参数")
            return

        coverage_master.dump(classes, port, jobname, args.old_commit, args.new_commit, args.old_branch, args.job_url)


def test_generate():
    print("start")
    coverage_master = CoverageMaster('test', 'test', 'test', 'test')
    diffcov_txt = "/Users/OVERFLY/downloads/output-insurance-waimai-blankerror/src_meituan.insurance.\
    unification.wmaccess2018-03-16-13-15-07/insurance-waimai-package/diffcov.txt"
    diffcov_txt = "/Users/OVERFLY/downloads/output-correct/src_meituan.train.train.insuranceapi2018-03-21-16-39-26/\
    travel-insurance/diffcov.txt"
    diffcov_txt = "/Users/OVERFLY/downloads/output/src_meituan.zc.cos.acquirerregister2018-03-14-15-14-15/\
    zcm-acquirer-register/diffcovtest.txt"
    src_html = os.path.join(root_path, "thirdparts/diffcov.html")
    target_html = "/Users/OVERFLY/downloads/output-diffcovzero/diff2html/test_index.html"
    coverage_master.get_diff_cov_to_html(diffcov_txt, src_html, target_html)


if __name__ == '__main__':
    if sys.version_info[0] < 3:
        reload(sys)
        sys.setdefaultencoding('utf-8')
    main()
