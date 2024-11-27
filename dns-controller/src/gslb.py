#!/usr/bin/env python

import argparse
import os
import logging
import requests
import json
import time
import base64
from apscheduler.schedulers.blocking import BlockingScheduler
from kubernetes import client, config,utils,dynamic
from kubernetes.client.rest import ApiException
import jwt
import yaml
import ipaddress

import requests
import urllib3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
gslb_sched = BlockingScheduler()
# Disable certificate warnings

access_token = None
access_token_expiration = None
    


if hasattr(requests.packages.urllib3, 'disable_warnings'):
    requests.packages.urllib3.disable_warnings()

if hasattr(urllib3, 'disable_warnings'):
    urllib3.disable_warnings()

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def delDnsEndpoints(spaceClient: client.ApiClient,record):
    api = client.CustomObjectsApi(spaceClient)
    try:
        api.delete_namespaced_custom_object(group="externaldns.k8s.io", version="v1alpha1",plural="dnsendpoints", namespace="default",name=record)
        logging.info(f"deleted entry for {record}")
    except ApiException as e:
        logging.error(f"failed to delete entry for {record}")
        raise

def getDnsEndpoints(spaceClient: client.ApiClient):
    api = client.CustomObjectsApi(spaceClient)
    try:
        dnsendpoints = api.list_namespaced_custom_object(group="externaldns.k8s.io", version="v1alpha1",plural="dnsendpoints", namespace="default")
        return dnsendpoints
    except ApiException as e:
        logging.error(f"failed to get list of dns endpoints")
        raise


def apply_dict(spaceClient: client.ApiClient , manifest: dict):
    api_version = manifest.get("apiVersion").split("/")
    group = api_version[0]
    version = api_version[1]
    kind = manifest.get("kind")
    resource_name = manifest.get("metadata").get("name")
    namespace = manifest.get("metadata").get("namespace")
    api = client.CustomObjectsApi(spaceClient)

    try:
        api.patch_namespaced_custom_object(group=group, version=version,plural="dnsendpoints", namespace=namespace,name=resource_name,body=manifest)
        logging.info(f"{namespace}/{resource_name} patched")
    except ApiException as e:
        logging.error(f"unable to patch entry {resource_name} {e.body}")
        if e.reason == "Not Found":
            try:
                api.create_namespaced_custom_object(group=group, version=version,plural="dnsendpoints", namespace=namespace,body=manifest)
                logging.info(f"{namespace}/{resource_name} created")
            except ApiException as e2:
                logging.error(f"unable to create entry {resource_name} {e2.body}")


def get_domain_bindings(space,ucpClient):
    managed = managed_domains
    api = client.CustomObjectsApi(ucpClient)
    api.api_client.configuration.host = f"{ucpClient.configuration.host}/space/{space}"
    try:
        allocated= []
        bindings = api.list_namespaced_custom_object(group="networking.tanzu.vmware.com", version="v1alpha1",plural="domainbindings",namespace="default")
        for binding in bindings["items"]:
            if "status" in binding:
                for condition in binding["status"]["conditions"]:
                    if condition["type"] == "DomainAllocated" and condition["status"]:
                        for md in managed:
                            if md in binding["spec"]["domain"]:
                                allocated.append(binding)  
        return allocated

    except ApiException as e:
        logging.error(f"failed to get domainbinding data for {space}")
        raise


def getAccessToken(csp_host,csp_token,tp_host,tpsm):

    if tpsm:
        logging.info("tpsm detected using UAA auth")
        client = "tp_cli_app"
        client_secret = "tanzu_intentionally_not_a_secret"
        authcode_bytes = base64.b64encode(f"{client}:{client_secret}".encode('utf-8'))
        authcode = authcode_bytes.decode('utf-8')
        headers = {
            "Authorization":f"Basic {authcode}",
            "Content-Type":"application/x-www-form-urlencoded",
            "x-cf-encoded-credentials": "true"
        }
        payload = {
            'client_id': client,
            'grant_type': 'password',
            'password': password,
            'username': username
        } 
        expire_time = -1
        try:
            response = requests.post(f"{tp_host}/auth/oauth/token", data=payload, headers=headers,verify=False)
            response.raise_for_status()
        except Exception as except_ce:
            logging.error(except_ce)
            return None
        else:
            access_token = response.json()["access_token"]

            expires_in = response.json()["expires_in"]
            expire_time = time.time() + expires_in
            return access_token,expire_time

    else:    
        try:
            response = requests.post('https://%s/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=%s' % (csp_host,csp_token))
            response.raise_for_status()
        except Exception as e:
            logging.error(e)
            return None
        else:
            access_token = response.json()['access_token']
            expires_in = response.json()['expires_in']
            expire_time = time.time() + expires_in
            return access_token, expire_time


def set_global_token():
    logger.info("checking if token is expired")
    global access_token_expiration
    global access_token
    if time.time() > access_token_expiration:
        logger.info("udpating refresh token")
        access_token, access_token_expiration =  getAccessToken(csp_host,csp_token,tp_host,tpsm)

def get_global_token():
    return access_token
    

def run():
    
    gslb_data = {}

    set_global_token()
   

    logger.info("creating ucp client")
    ucpConfig = client.Configuration()
    ucpConfig.verify_ssl = True
    ucpConfig.host = f"{tp_host}/org/{org_id}/project/{project_id}"
    ucpConfig.api_key = {"authorization": "Bearer " + access_token}
    ucpClient = client.ApiClient(ucpConfig)
    project_bindings = []
    for space in spaces:
        ucpClient.configuration.host = f"{tp_host}/org/{org_id}/project/{project_id}"
        logger.info(f"generating space gslb data for {space}")
        
        domainBindings = get_domain_bindings(space,ucpClient)
        project_bindings +=domainBindings
        print(domainBindings)
       

    desiredServices = []

    #reconcile domain bindings into unique domains and their pools members for now everything is round robin
    for binding in project_bindings:
        domain = binding["spec"]["domain"]
        members = []
        for address in binding["status"]["addresses"]:
            member = address["value"]
            if address["type"] == "IPAddress":
                recordType = "A"
            else:
                recordType = "CNAME"
            if domain in gslb_data:
                if gslb_data[domain]["record"]["spec"]["endpoints"][0]["recordType"] != recordType:
                    logging.error(f"unable to update record for {domain}, coflicting entry types. CNAME and A record detected")
                    continue
                if member not in gslb_data[domain]["record"]["spec"]["endpoints"][0]["targets"]:
                    gslb_data[domain]["record"]["spec"]["endpoints"][0]["targets"].append(member)
            else:
                members.append(member)
            
                record =  {
                    "apiVersion": "externaldns.k8s.io/v1alpha1",
                    "kind": "DNSEndpoint",
                    "metadata": {
                        "name": domain,
                        "namespace": "default"
                    },
                    "spec": {
                        "endpoints": [
                        {
                            "dnsName": domain,
                            "recordTTL": 30,
                            "recordType": recordType,
                            "targets": members
                        }
                        ]
                    }
                }   

                gslb_data[domain] = {}
                gslb_data[domain]["record"] = record

    for _, serv in gslb_data.items():

        desiredServices.append(serv['record']['metadata']['name'])
        try:
            ucpClient.configuration.host = f"{tp_host}/org/{org_id}/project/{project_id}/space/{deploy_space}"
            logging.debug(serv)
            logging.info(ucpClient.configuration.host)
            apply_dict(ucpClient,serv["record"])
        except Exception as ex:
            raise Exception('%s' % (ex))
    

    # delete any records that are no longer needed 
    try:
        #get current records
        ucpClient.configuration.host = f"{tp_host}/org/{org_id}/project/{project_id}/space/{deploy_space}"
        current_records = getDnsEndpoints(ucpClient)
        print(current_records)
        for entry in current_records["items"]:
            if entry["metadata"]["name"] not in desiredServices:
                logger.info(f"deleting {entry["metadata"]["name"]}")
                delDnsEndpoints(ucpClient,entry["metadata"]["name"])                
    except Exception as ex:
            raise Exception('%s' % (ex))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--tphost',
                        help='FQDN or IP address of the Tanzu Platform API,including the scheme',default=os.environ.get('TP_HOST'))
    parser.add_argument('--spaces',
                        help='comma separated list of spaces to watch',default=os.environ.get('SPACES'))
    parser.add_argument('--tpsm',
                        help='whether or not you are running self manage(true or false)',default=os.environ.get('TPSM'))
    parser.add_argument('--tpsmuser',
                        help='username for tspm, this should be an admin user',default=os.environ.get('TPSM_USER'))
    parser.add_argument('--tpsmpass',
                        help='password for tpsm user',default=os.environ.get('TPSM_PASS'))
    parser.add_argument('--orgid',
                        help='org id',default=os.environ.get('ORG_ID'))
    parser.add_argument('--projectid',
                        help='id of the project to use',default=os.environ.get('PROJECT_ID'))
    parser.add_argument('--manageddomains',help='comma separated list of domains that should be managed',default=os.environ.get('MANAGED_DOMAINS'))
    parser.add_argument('--project',
                        help='name of the project',default=os.environ.get('PROJECT'))
    parser.add_argument('--csptoken', help='CSP token for api calls',default=os.environ.get('CSP_TOKEN'))
    parser.add_argument('--deploymentspace', help='space name that the controller is deployed to',default=os.environ.get('DEPLOYMENT_SPACE'))



    args = parser.parse_args()

    if args:
        # If not specified on the command-line, prompt the user for the
        # controller IP address and/or password

        csp_token = None
        csp_host = None
        tp_host = args.tphost
        tpsm = args.tpsm
        username = args.tpsmuser
        password = args.tpsmpass
        spaces_list = args.spaces
        project_id = args.projectid
        org_id = args.orgid
        project_name = args.project
        managed_domains = args.manageddomains.split(",")
        spaces = spaces_list.split(",")
        csp_token = args.csptoken
        csp_host = "console.tanzu.broadcom.com"
        deploy_space = args.deploymentspace
        
        try:
            logging.info("getting initial token")
            access_token, access_token_expiration = getAccessToken(csp_host,csp_token,tp_host,tpsm)
            if access_token is None:
                raise Exception("Request for access token failed.")
        except Exception as e:
            logging.error(e)
        else:
            logging.info("access token recieved")
        
        gslb_sched.add_job(id='run gslb job',func=run,trigger='interval',seconds=10)
        gslb_sched.start()

    else:
        parser.print_help()

    
