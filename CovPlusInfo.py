#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import os
from time import sleep
from qcs_env_coverage.venv import requests
from qcs_env_coverage.CovLogger import CoverageLog
from qcs_env_coverage.venv.bs4 import BeautifulSoup

clog = CoverageLog.get_logger(os.path.basename(__file__))


def get_login_data():
    url = "https://ssosv.sankuai.com/login?service=https%3A%2F%2Fsso.sankuai.com" \
          "%2Fproxy%3FclientService%3Dhttp%253A%252F%252Fplus.sankuai.com%252Flogin" \
          "%253Furl%253Dhttp%25253A%25252F%25252Fplus.sankuai.com%25252F "
    info = requests.get(url, verify=False)
    sleep(1)
    soup = BeautifulSoup(info.text, "html.parser")
    inputs = soup.find_all("input")

    login_data = {
        "username": "lqJempWcnpmaoaWp",
        "password": "fpeZqZiZqZukpmFoYw==",
        "service": "https://sso.sankuai.com/proxy?clientService=http%3A%2F%2Fplus.sankuai.com"
                   "%2Flogin%3Furl%3Dhttp%253A%252F%252Fplus.sankuai.com%252F",
        "lt": inputs[-3].attrs["value"],
        "execution": inputs[-1].attrs["value"],
        "_eventId": "submit",
    }

    response = requests.request("POST", url, data=login_data, verify=False, headers={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/54.0.2840.71 Safari/537.36"})
    sleep(1)
    cookie = ""
    for item in response.cookies.items():
        cookie += "{}={};".format(item[0], item[1])
    cookie = cookie[:-1]

    soup = BeautifulSoup(response.text, "html.parser")
    inputs = soup.find_all("input")
    sid = inputs[0].attrs["value"]
    time = inputs[1].attrs["value"]
    sign = inputs[2].attrs["value"]

    plus_param = {
        "SID": sid,
        "time": time,
        "sign": sign,
    }
    clog.info(plus_param)
    plus_url = "http://plus.sankuai.com/login?url=http://plus.sankuai.com/"
    headers = {
        "Cookie": cookie,
        "Host": "plus.sankuai.com",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/54.0.2840.71 Safari/537.36",
        "Upgrade-Insecure-Requests": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.8,en;q=0.6",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Content-Length": "90",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "null"
    }

    response = requests.request("POST", plus_url, data=plus_param, headers=headers, allow_redirects=False, verify=False)
    sleep(1)
    cookie = ""
    for item in response.cookies.items():
        cookie += "{}={};".format(item[0], item[1])
    cookie = cookie[:-1]
    clog.info(cookie)
    return {"Cookie": cookie}


class PlusRecord(object):
    def __init__(self, plus_name, template_name, ip, branch, git_url=None):
        self.base_url = "http://plus.sankuai.com"
        self.plus_name = plus_name
        self.template_name = template_name
        self.username = "lqJempWcnpmaoaWp"
        self.password = "fpeZqZiZqZukpmFoYw=="
        self.branch = branch
        self.host = ip

        self.flag = False
        self.git_url = git_url
        if self.git_url:
            self.git = self.git_url
        else:
            init_info = self.init()
            if init_info is not None:
                self.flag = True
                self.git = init_info["Repository"]
                self.commit = init_info["Commit"]

    def init(self):
        plus_detail = self.get_item_info_by_name()
        if plus_detail is None or "Id" not in plus_detail:
            clog.error("Failed to get the Plus release {} config".format(self.plus_name))
            return None

        git_url = plus_detail["Repository"]
        # commit = self.get_commit_by_host()

        return {"Repository": git_url, "Commit": None}

    def get_commit_by_host(self):
        """
        TODO: Plus provides the task detail interface ==> to get the commit under host.
        """
        return None

    def get_item_info_by_name(self):
        """
        Get a deployment detail
        :return:
        """
        req_url = "{}{}?release_name={}".format(self.base_url, "/release_detail", self.plus_name)
        response = requests.get(req_url, verify=False)
        sleep(1)
        if response.status_code != 200:
            return None
        return response.json()

    def get_all_deploy_record_by_id(self, release_id):
        """
        Get deployment records.
        The ugly implementation is used now, and the interface is later coordinated.
        :param release_id:
        :return:
        """
        url = "{}{}".format(self.base_url, "/release/{}/joblist?offset=0&limit=1000".format(release_id))
        sleep(1)
        clog.info(url)
        try:
            response = requests.get(url)
            sleep(1)
            if response.status_code != 200:
                clog.error("Failed to get all deploy records for Plus")
                return None
            return response.json()

        except Exception as e:
            clog.error("error {}".format(e))
            return None

    def get_template_deploy_record_by_id(self, release_id):
        """
        Get template env deploy info, template.
        The template is the name of the template defined by plus.
        :param release_id:
        :return:
        """
        records = []
        raw_detail = self.get_all_deploy_record_by_id(release_id)

        if raw_detail is not None:
            for item in raw_detail:
                if item["TemplateName"] == self.template_name:
                    records.append(item)
        return records

    def get_template_last_deploy_record_by_name(self, records, release_id):
        """
        :param records:
        :param release_id:
        :return:
        """
        last_daemon_job_id = records[0]["DaemonJobId"]
        last_detail_url = "{}/ui/release/{}/job/{}/detail".format(self.base_url, release_id, last_daemon_job_id)

        clog.info(last_detail_url)
        try:
            response = requests.get(last_detail_url,
                                    headers={"Cookie": "deploytoken=91865de3-16f1-456c-9b88-311a1dfbb8e6"},
                                    verify=False)

            sleep(1)
            if response.status_code != 200:
                return None
            return response.json()
        except Exception as e:
            clog.error("error {}".format(e))
            return None

    def get_all(self):
        url = "{}/release/list/all".format(self.base_url)
        response = requests.get(url)
        clog.info(response.text)

    def output_init_info(self):
        clog.info(self.git)
        clog.info(self.branch)
        clog.info(self.commit)
        clog.info(self.host)


if __name__ == "__main__":
    template_n = "test"
    plus_n = "meituan.qcs.service.messagecenter"

    p_record = PlusRecord(plus_n, template_n, "10.21.250.248", "master")
    if p_record.git_url is None:
        p_record.output_init_info()
