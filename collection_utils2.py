from generic_utilities import setup_logging, generic_config_parser, handle_error
import argparse
import json
import traceback
import os
import logging
import csv
from mimir import Mimir
from pprint import pprint as pp
import datetime
import time
from scp import SCPClient
import paramiko
import smtplib
import socket
import requests
code_dir_path = os.path.abspath(os.path.dirname(__file__))
log = logging.getLogger(__name__)

login_url = 'https://cloudsso.cisco.com/as/token.oauth2?client_id=nossplunknpres.gen&grant_type=client_credentials&client_secret=$NP-USrobot4&scope=openid'
r = requests.post(login_url)
token = r.json()
#print token
def fetch_collectors():
    m = mimir_connect()
    collectors = m.np.collectors.get()
    master_collector_dict = {}
    for collector in collectors:
        company_key = int(collector.cpyKey)
        active_collector = str(collector.collector)
        if company_key not in master_collector_dict:
            master_collector_dict[company_key] = []
        master_collector_dict[company_key].append(active_collector)
    return master_collector_dict

def mimir_connect():
    login_url = 'https://cloudsso.cisco.com/as/token.oauth2?client_id=nossplunknpres.gen&grant_type=client_credentials&client_secret=$NP-USrobot4&scope=openid'
    r = requests.post(login_url)
    token = r.json()
    #print token
    g_conf = generic_config_parser()
    user_section = "mimir_user"
    user_credentials = g_conf.fetch_conf_param(user_section)
    mimir_env = g_conf.fetch_conf_param("mimir_env")
    #mimir_instance = Mimir(username=user_credentials["username"],password=user_credentials["passurl=mimir_env["url"])url=mimir_env["url"])
    mimir_instance = Mimir(access_token=token['access_token'],url=mimir_env["url"])
    return mimir_instance

def fetch_all_companies_from_np():
    m = mimir_connect()
    return [i.cpyKey for i in m.np.companies.get()]

def fetch_np_api_list(categories):
    command_list = []
    np_conf_file_path = os.path.join(code_dir_path, "..", "conf", "collection_packages", 'np.json')
    if os.path.exists(np_conf_file_path):
        with open(np_conf_file_path, "r") as np_command_file:
            command_master_list = json.load(np_command_file)
            for category in categories:
                command_list.extend(command_master_list[category])
    else:
        log.info("np.json file could not be found")
    return command_list

def fetch_np_profile_name_list():
    profile_name_list = []
    np_conf_file_path = os.path.join(code_dir_path, "..", "conf", "collection_packages", 'np.json')
    if os.path.exists(np_conf_file_path):
        with open(np_conf_file_path, "r") as np_command_file:
            command_master_list = json.load(np_command_file)
            profile_name_list = command_master_list.keys()
    else:
        log.info("np.json file could not be found")
    return profile_name_list

def fetch_master_company_list(mimir_instance, cluster_names):
    try:
        company_list = []
        for cluster_name in cluster_names:
            companies = mimir_instance.np.companies.get(clusterName=cluster_name)
            for company in companies:
                company_key = str(company.cpyKey)
                if company_key not in company_list:
                    company_list.append(company_key)
        return company_list
    except:
        error_msg = "Issue with fetching master company list from Mimir"
        handle_error_without_logging(error_msg, str(traceback.format_exc()))
        return []

def fetch_entitled_company_list(cluster="US", mimir_instance=None):
    try:
        cpylist = []
        if cluster == "US":
            #US clusters are US1 to US4
            cluster_names = ["%s%s" % (cluster, cluster_id) for cluster_id in range(1,5)]
        else:
            cluster_names = [cluster]

        if not mimir_instance:
            mimir_instance = mimir_connect()
    except:
        error_msg = "Issue with fetching entitled company list from Mimir"
        handle_error_without_logging(error_msg, str(traceback.format_exc()))
        return [], []
    try:
        g_conf = generic_config_parser()
        user_section = "mimir_user"
        user_credentials = g_conf.fetch_conf_param(user_section)
        companies_entitled = mimir_instance.np.companies_entitled.get(userId=user_credentials["username"])
        master_company_list = fetch_master_company_list(mimir_instance, cluster_names)
        entitled_company_list = []
        for company_entry in companies_entitled:
            company_key = str(company_entry.cpyKey)
            if (company_key not in entitled_company_list) and (company_key in master_company_list):
                entitled_company_list.append(company_key)
        return entitled_company_list, master_company_list
    except:
        error_msg = "Issue with fetching entitled company list from Mimir"
        handle_error_without_logging(error_msg, str(traceback.format_exc()))
        return [], []


def fetch_onboarded_companies_from_customer_csv(data_type="int"):
    company_list = []
    g_conf = generic_config_parser()

    path_to_conf = os.path.join(code_dir_path, "..", "conf")
    env_var = g_conf.fetch_conf_param("environment_variables")
    customer_csv_filename = env_var["customer_csv"]
    customer_csv_filepath = os.path.join(path_to_conf, customer_csv_filename)

    if os.path.exists(customer_csv_filepath):
        company_entries = csv.DictReader(open(customer_csv_filepath))
        for cpy_entry in company_entries:
            if cpy_entry['roles'].lower() == "admin":
                if data_type == "int":
                    cpy_key = int(cpy_entry['cpyKey'])
                else:
                    cpy_key = str(cpy_entry['cpyKey'])
                if cpy_key not in company_list:
                    company_list.append(cpy_key)
    return company_list

def fetch_cluster_onboarded_companies_from_customer_csv(data_type="int"):
    company_list = []
    g_conf = generic_config_parser()
    path_to_conf = os.path.join(code_dir_path, "..", "conf")
    env_var = g_conf.fetch_conf_param("environment_variables")
    customer_csv_filename = env_var["cluster_csv"]
    customer_csv_filepath = os.path.join(path_to_conf, customer_csv_filename)

    if os.path.exists(customer_csv_filepath):
        company_entries = csv.DictReader(open(customer_csv_filepath))
        for cpy_entry in company_entries:
            print(str(cpy_entry))
            if cpy_entry['roles'].lower() == "admin":
                if data_type == "int":
                    cpy_key = int(cpy_entry['cpyKey'])
                else:
                    cpy_key = str(cpy_entry['cpyKey'])
                if cpy_key not in company_list:
                    company_list.append(cpy_key)
    return company_list

def fetch_epoch_for_day_start(day_prefix=None):
    #fetch the epoch equivalent for the start of the day
    try:
        date_pattern = '%Y-%m-%dT%H:%M:%S'
        if not day_prefix:
            #if not passed use current day
            current_time = datetime.datetime.now()
            day_prefix = "%s-%s-%s" % (current_time.year, \
                                       current_time.strftime("%m"), \
                                       current_time.strftime("%d")
                                       )
        date_time_str = day_prefix + "T00:00:00"
        corresponding_epoch = int(time.mktime(time.strptime(date_time_str, date_pattern)))
        return corresponding_epoch
    except:
        error_msg = "Issue with fetching epoch value for %s " % day_prefix
        handle_error(error_msg, str(traceback.format_exc()))

def fetch_epoch_from_ts(date_time_str):
    #fetch the epoch equivalent for the start of the day
    try:
        date_pattern = '%Y-%m-%dT%H:%M:%S'
        corresponding_epoch = int(time.mktime(time.strptime(date_time_str, date_pattern)))
        return corresponding_epoch
    except:
        error_msg = "Issue with fetching epoch value for %s " % date_time_str
        handle_error(error_msg, str(traceback.format_exc()))

def fetch_timestamp_from_epoch(current_epoch):
    #fetch the timestamp equivalent for the given epoch
    try:
        converted_date_format = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(current_epoch))
        return converted_date_format
    except:
        error_msg = "Issue with fetching timestamp value for epoch - %s " % current_epoch
        handle_error(error_msg, str(traceback.format_exc()))

def check_folder_existence(forwarder_ip, destination_cpykey_folder, user):
        ssh_client = create_ssh_client(forwarder_ip, 22, user)
        transport = ssh_client.get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            sftp.chdir(destination_cpykey_folder)
        except IOError:
            sftp.mkdir(destination_cpykey_folder)
        ssh_client.close()
        sftp.close()

def create_ssh_client(server, port, user):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, timeout=120)
    return client

class GetArguments:
    def __init__(self):
        self.processes()
        self.get_generic_args()
        self.get_common_elements_from_args()

    def processes(self):
        try:
            self.parser_object = argparse.ArgumentParser()
            self.g_conf = generic_config_parser()
            self.args_dict = {}
        except:
            error_msg = "issue with creating argsparse object"
            error_content = str(traceback.format_exc())
            log.error(error_msg)
            log.error(error_content)

    def get_generic_args(self):
        try:
        #common
            print "get_generic_args strated"
            self.parser_object.add_argument("---cpykey",type=str)
            self.parser_object.add_argument("---mimirhost",type=str)
            self.parser_object.add_argument("---mongoconfname",type=str)
            self.parser_object.add_argument("---collectionname",type=str)
            self.parser_object.add_argument("---databasename",type=str)
            self.parser_object.add_argument("---mongoport",type=int)
            self.parser_object.add_argument("---mongohost",type=str)
            self.parser_object.add_argument("---collectionpath",type=str)
            #cli
            self.parser_object.add_argument("---command",type=str)
            self.parser_object.add_argument("---package",type=str)
            self.parser_object.add_argument("---device",type=int)
            self.parser_object.add_argument("---extra",type=int)
            self.generic_args = self.parser_object.parse_args()
            print "get_generic_args ended", self.generic_args
        except:
            error_msg = "issue with adding and parsing arguments"
            error_content = str(traceback.format_exc())
            log.error( error_msg)
            log.error(error_content)

    def get_common_elements_from_args(self):
        #cpykey
        if self.generic_args.cpykey is None:
            #snippet for getting the entitiled command list from csv
            self.args_dict['cpyKey'] = '81714'
        else:
            self.args_dict['cpyKey'] = self.generic_args.cpykey
        #mimir host
        if self.generic_args.mimirhost is None:
            mimir_credentials = self.g_conf.fetch_conf_param("mimir_env")
            self.args_dict["mimir_host"] = mimir_credentials["url"]
        else:
            self.args_dict["mimir_host"] = self.generic_args.mimirhost
        #mongo host name
        if self.generic_args.mongoconfname is None:
            self.args_dict["mongo_conf_name"] = 'mongo_conf_2'
            self.mongo_credentials = self.g_conf.fetch_conf_param("mongo_conf_2")
        else:
            self.args_dict["mongo_conf_name"] = self.generic_args.mongoconfname
            self.mongo_credentials = self.g_conf.fetch_conf_param(self.generic_args.mongoconfname)
        #mongo collection name
        if self.generic_args.collectionname is None:
            self.args_dict["collection_name"] = self.mongo_credentials["collection_name"]
        else:
            self.args_dict["collection_name"] = self.generic_args.collectionname
        #mongo database name
        if self.generic_args.databasename is None:
            self.args_dict["database_name"] = self.mongo_credentials["database_name"]
        else:
            self.args_dict["database_name"] = self.generic_args.database
        #mongo port
        if self.generic_args.mongoport is None:
            self.args_dict["port"] = self.mongo_credentials["port"]
        else:
            self.args_dict["port"] = self.generic_args.mongoport
        #mongo host
        if self.generic_args.mongohost is None:
            self.args_dict["host"] = self.mongo_credentials["host"]
        else:
            self.args_dict["host"] = self.generic_args.mongohost

    def get_cli_arguments(self):
        #command name
        if self.generic_args.command is None:
            self.args_dict["command"] = ''
        else:
            self.args_dict["command"] = self.generic_args.command
        #package name
        if self.generic_args.package is None:
            self.args_dict["package"] = 'default'
        else:
            self.args_dict["package"] = self.generic_args.package
        #device Id
        if self.generic_args.device is None:
            pass
        else:
            self.args_dict["deviceId"] = self.generic_args.device
        #collection path
        if self.generic_args.collectionpath is None:
            self.collection_path_details = self.g_conf.fetch_conf_param("collection_path")
            self.args_dict["collectionpath"] = self.collection_path_details["cli_base_path"]
        else:
            self.args_dict["collectionpath"] = self.generic_args.collectionpath
        return self.args_dict

    def get_np_arguments(self):
        return self.args_dict

    def get_syslog_arguments(self):
        self.args_dict['mongo_credentials'] = self.mongo_credentials
        #collection path
        if self.generic_args.collectionpath is None:
            self.collection_path_details = self.g_conf.fetch_conf_param("collection_path")
            self.args_dict["collectionpath"] = self.collection_path_details["syslog_base_path"]
        else:
            self.args_dict["collectionpath"] = self.generic_args.collectionpath
        return self.args_dict

if __name__ == '__main__':
    setup_logging()
    onboarded_list = fetch_onboarded_companies_from_customer_csv(data_type="str")
    print len(onboarded_list)

    emear_comp_list, _ = fetch_entitled_company_list("EMEA")
    print "EMEAR entitled_company_list"
    print len(emear_comp_list)
    print set(onboarded_list).intersection(emear_comp_list)

    us_comp_list, _ = fetch_entitled_company_list("US")
    print "US entitled_company_list"
    print len(us_comp_list)
    print len(set(onboarded_list).intersection(us_comp_list))

    #testing timestamp conversions
    print "fetch_timestamp_from_epoch, 1st Jan 2018 - ", fetch_timestamp_from_epoch(fetch_epoch_for_day_start("2018-01-01"))
    print "fetch_timestamp_from_epoch, Today - ",fetch_timestamp_from_epoch(fetch_epoch_for_day_start())

