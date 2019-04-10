#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#

import os
from errno import errorcode
from qcs_env_coverage.venv import connector
from qcs_env_coverage.CovLogger import CoverageLog

clog = CoverageLog.get_logger(os.path.basename(__file__))


class CoverageDataBaseOperator(object):
    def __init__(self, database_name, host, port, user, password, charset):
        self.database_name = database_name
        self.host = host
        self.user = user
        self.port = port
        self.password = password
        try:
            self.con = connector.connect(user=self.user, password=self.password, host=self.host, port=port,
                                         database=self.database_name, charset=charset)
            self.cursor = self.con.cursor()
        except connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                clog.error("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                clog.error("Database does not exist")
            else:
                clog.error(err)

    def select_sql(self, sql):
        clog.info(sql)
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def execute_sql(self, sql):
        self.cursor.execute(sql)
        self.con.commit()


def get_jenkins_url_by_jobname(jobname):
    """
    :param jobname:
    :return:
    """
    dbo = CoverageDataBaseOperator("qqeeqqU=", "YmJeaWJebW9fag==", "5002", "qqeeqqWPrA==", "66SxmfCrJUif2k", "utf8")

    sql = """
            select
                case WHEN job_url is NULL THEN ""
                else job_url
                END as job_url
            from cover_rage_job_org where job_name = "{}"
        """.format(jobname)
    result = dbo.select_sql(sql)

    if len(result) > 0:
        return result[0][0]
    return None
