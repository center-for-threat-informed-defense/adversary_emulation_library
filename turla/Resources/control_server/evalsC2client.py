#!/usr/bin/python3

# ---------------------------------------------------------------------------
# evalsC2client.py - Interact with Evals C2 server.

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: 
# ./evalsC2client.py --set-task [GUID] "task string"

# Revision History:

# --------------------------------------------------------------------------- 

import argparse
import json
import pprint
import requests
import sys
import time
import traceback

from datetime import datetime, timedelta

API_RESP_TYPE_KEY = 'type'
API_RESP_STATUS_KEY = 'status'
API_RESP_DATA_KEY = 'data'
API_RESP_STATUS_SUCCESS = 0

RESP_TYPE_CTRL = 0 # API control messages (for error messages, generic success messages). Will contain string data
RESP_TYPE_VERSION = 1 #version message (for GetVersion). Will contain string data
RESP_TYPE_CONFIG = 2 # config message (for GetConfig). Will contain json data
RESP_TYPE_SESSIONS = 3 # C2 sessions message (for GetSessionByGuid and GetSessions). Will contain json data
RESP_TYPE_TASK_CMD = 4 # task command message (for GetTaskCommandBySessionId and GetBootstrapTask). Will contain string data
RESP_TYPE_TASK_OUTPUT = 5 # task output message (for GetTaskOutputBySessionId and GetTaskOutput). Will contain string data
RESP_TYPE_TASK_INFO = 6 # task data message (for GetTask). Will contain json data

TASK_STATUS_KEY = 'taskStatus'
TASK_GUID_KEY = 'guid'
TASK_COMMAND_KEY = 'command'
TASK_OUTPUT_KEY = 'taskOutput'

TASK_STATUS_NEW = 0
TASK_STATUS_PENDING = 1
TASK_STATUS_FINISHED = 2
TASK_STATUS_DISCARDED = 3

VERBOSE_OUTPUT = False

# Custom exception for handling API responses
class ApiResponseException(Exception):
    pass
    
def print_stderr(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    
def verbose_print(*args, **kwargs):
    if VERBOSE_OUTPUT:
        print(*args, **kwargs)

# ToDo - need to add unit tests for this script

def validate_api_resp_format(resp_dict):
    """Throws ApiResponseException when detecting an invalid API response format (missing JSON field, etc)"""
    
    if API_RESP_TYPE_KEY not in resp_dict:
        raise ApiResponseException('Malformed API response: missing API response type key "' + API_RESP_TYPE_KEY + '"')
    elif not isinstance(resp_dict[API_RESP_TYPE_KEY], int):
        raise ApiResponseException('Malformed API response: response type is not an int.')
    if API_RESP_STATUS_KEY not in resp_dict:
        raise ApiResponseException('Malformed API response: missing API response status key "' + API_RESP_STATUS_KEY + '"')
    elif not isinstance(resp_dict[API_RESP_STATUS_KEY], int):
        raise ApiResponseException('Malformed API response: response status is not an int.')
    if API_RESP_DATA_KEY not in resp_dict:
        raise ApiResponseException('Malformed API response: missing API response data key "' + API_RESP_DATA_KEY + '"')
        
    # verify response type and data type
    resp_type = resp_dict[API_RESP_TYPE_KEY]
    resp_data = resp_dict[API_RESP_DATA_KEY]
    if resp_type in [RESP_TYPE_CTRL, RESP_TYPE_VERSION, RESP_TYPE_TASK_CMD, RESP_TYPE_TASK_OUTPUT]:
        if not isinstance(resp_data, str):
            raise ApiResponseException('Malformed API response: expected str data type for response type {}'.format(resp_type))
    elif resp_type in [RESP_TYPE_CONFIG, RESP_TYPE_TASK_INFO] and not isinstance(resp_data, dict):
        raise ApiResponseException('Malformed API response: expected dictionary data type for response type {}'.format(resp_type))
    elif resp_type == RESP_TYPE_TASK_INFO:
        if TASK_STATUS_KEY not in resp_data:
            raise ApiResponseException('Malformed API response: missing task status key "' + API_RESP_TYPE_KEY + '"')
        if TASK_GUID_KEY not in resp_data:
            raise ApiResponseException('Malformed API response: missing task GUID key "' + TASK_GUID_KEY + '"')
        if TASK_COMMAND_KEY not in resp_data:
            raise ApiResponseException('Malformed API response: missing task command key "' + TASK_COMMAND_KEY + '"')
    elif resp_type == RESP_TYPE_SESSIONS:
        if resp_data is not None and not isinstance(resp_data, list):
            raise ApiResponseException('Malformed API response: expected None or list data type for response type {}'.format(resp_type))
        

def verify_api_resp_success(resp_dict):
    """Throws ApiResponseException if API response indicates failure."""
    
    if resp_dict[API_RESP_STATUS_KEY] != API_RESP_STATUS_SUCCESS:
        raise ApiResponseException('Received unsuccessful API response: ' + resp_dict[API_RESP_DATA_KEY])
        
        
def extract_response(api_resp_str, expected_type):
    resp_dict = json.loads(api_resp_str)
    validate_api_resp_format(resp_dict)
    verify_api_resp_success(resp_dict)
    
    resp_type = resp_dict[API_RESP_TYPE_KEY]
    if resp_type != expected_type:
        raise ApiResponseException('Expected response type {0}, got {1}'.format(expected_type, resp_type))
    return resp_dict[API_RESP_DATA_KEY]

    
def extract_and_print_response(response, resp_type):
    try:
        resp_data = extract_response(response.text, resp_type)
        if resp_type in [RESP_TYPE_CTRL, RESP_TYPE_VERSION, RESP_TYPE_TASK_CMD, RESP_TYPE_TASK_OUTPUT]:
            # string response data
            print(resp_data)
        elif resp_type in [RESP_TYPE_CONFIG, RESP_TYPE_TASK_INFO]:
            # dictionary data
            print(json.dumps(resp_data, sort_keys=True, indent=4))
        elif resp_type == RESP_TYPE_SESSIONS:
            # None or list data
            if resp_data is None:
                resp_data = []
            print(json.dumps(resp_data, sort_keys=True, indent=4))
    except ApiResponseException as e:
        print_stderr("ApiResponseException: {0}\nAPI response text:\n{1}\n".format(str(e), response.text))
    except Exception as e:
        print_stderr("Unhandled exception: {0}\nAPI response text:\n{1}\n".format(str(e), response.text))
        traceback.print_exc()

    
def extract_and_print_single_session_response(response):
    try:
        sessions = extract_response(response.text, RESP_TYPE_SESSIONS)
        print(json.dumps(sessions[0], sort_keys=True, indent=4))
    except ApiResponseException as e:
        print_stderr("ApiResponseException: {0}\nAPI response text:\n{1}\n".format(str(e), response.text))
    except Exception as e:
        print_stderr("Unhandled exception: {0}\nAPI response text:\n{1}\n".format(str(e), response.text))
        traceback.print_exc()

"""API Wrappers"""  

def get_server_version(port: str):
    url = "http://localhost:{0}/api/v1.0/version".format(port)
    r = requests.get(url)
    extract_and_print_response(r, RESP_TYPE_VERSION)


def get_server_config(port: str):
    url = "http://localhost:{0}/api/v1.0/config".format(port)
    r = requests.get(url)
    extract_and_print_response(r, RESP_TYPE_CONFIG)


def get_implant_sessions(port: str):
    url = "http://localhost:{0}/api/v1.0/sessions".format(port)
    r = requests.get(url)
    extract_and_print_response(r, RESP_TYPE_SESSIONS)


def get_session_by_guid(guid: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/".format(port) + guid
    r = requests.get(url)
    extract_and_print_single_session_response(r)


def delete_session(guid: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/delete/".format(port) + guid
    r = requests.delete(url)
    extract_and_print_response(r, RESP_TYPE_CTRL)


def get_task_by_session_id(guid: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/{1}/task".format(port, guid)
    r = requests.get(url)
    print(r.text)
    

def set_task_by_session_id(guid, task: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/{1}/task".format(port, guid)
    r = requests.post(url, task)
    extract_and_print_response(r, RESP_TYPE_TASK_INFO)


def delete_task_by_session_id(guid: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/{1}/task".format(port, guid)
    r = requests.delete(url)
    extract_and_print_response(r, RESP_TYPE_CTRL)

def get_task_output_by_session_id(guid: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/{1}/task/output".format(port, guid)
    r = requests.get(url)
    extract_and_print_response(r, RESP_TYPE_TASK_OUTPUT)

def delete_task_output_by_session_id(guid: str, port: str):
    url = "http://localhost:{0}/api/v1.0/session/{1}/task/output".format(port, guid)
    r = requests.delete(url)
    extract_and_print_response(r, RESP_TYPE_CTRL)
    
def get_bootstrap_task(handler: str, port: str):
    url = "http://localhost:{0}/api/v1.0/bootstraptask/".format(port) + handler
    r = requests.get(url)
    print(r.text)
    

def set_bootstrap_task(handler, task: str, port: str):
    url = "http://localhost:{0}/api/v1.0/bootstraptask/".format(port) + handler
    r = requests.post(url, task)
    extract_and_print_response(r, RESP_TYPE_CTRL)


def delete_bootstrap_task(handler: str, port: str):
    url = "http://localhost:{0}/api/v1.0/bootstraptask/".format(port) + handler
    r = requests.delete(url)
    extract_and_print_response(r, RESP_TYPE_CTRL)


""" FOR OPERATOR USABILITY """
def get_task_status(task_guid: str, port):
    url = 'http://localhost:{0}/api/v1.0/task/{1}'.format(port, task_guid)
    r = requests.get(url)
    task_data = extract_response(r.text, RESP_TYPE_TASK_INFO)
    return task_data[TASK_STATUS_KEY]
    

def get_task_output(task_guid: str, port):
    url = 'http://localhost:{0}/api/v1.0/task/{1}'.format(port, task_guid)
    r = requests.get(url)
    task_data = extract_response(r.text, RESP_TYPE_TASK_INFO)
    if TASK_OUTPUT_KEY in task_data.keys():
        return task_data[TASK_OUTPUT_KEY]
    else:
        return ""


def set_and_complete_task(session_guid, task: str, port: str, timeout: int):
    url = "http://localhost:{0}/api/v1.0/session/{1}/task".format(port, session_guid)
    response = requests.post(url, task)
    try:
        task_data = extract_response(response.text, RESP_TYPE_TASK_INFO)
        task_guid = task_data[TASK_GUID_KEY]
        task_command = task_data[TASK_COMMAND_KEY]
        verbose_print('Set task with ID {0} for session {1} with command {2}'.format(task_guid, session_guid, task_command))
        verbose_print('Waiting up to {0} seconds for task output'.format(timeout))
    
        now = datetime.now()
        timeout_deadline = now + timedelta(seconds=timeout)
        finished = False
        while (datetime.now() < timeout_deadline) and not finished:
            task_status = get_task_status(task_guid, port)
            if task_status in [TASK_STATUS_FINISHED, TASK_STATUS_DISCARDED]:
                finished = True
                break
            time.sleep(5)
        if not finished:
            # We timed out
            if task_status == TASK_STATUS_NEW:
                print_stderr('Timed out while waiting for implant with session ID {0} to pick up task {1}.'.format(session_guid, task_guid))
            elif task_status == TASK_STATUS_PENDING:
                print_stderr('Timed out while waiting for implant with session ID {0} to send output for task {1}.'.format(session_guid, task_guid))
        elif task_status == TASK_STATUS_DISCARDED:
            print_stderr('Task {1} was discarded for session ID {0}. Could not obtain output'.format(session_guid, task_guid))
        elif task_status == TASK_STATUS_FINISHED:
            task_output = get_task_output(task_guid, port)
            verbose_print('Received output for task {1} from session ID {0}:'.format(session_guid, task_guid))
            print(task_output)
    except ApiResponseException as e:
        print_stderr("ApiResponseException: {0}\nAPI response text:\n{1}\n".format(str(e), response.text))
    except Exception as e:
        print_stderr("Unhandled exception: {0}\nAPI response text:\n{1}\n".format(str(e), response.text))
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--get-version", action="store_true", help="get control server version")
    parser.add_argument("--get-config", action="store_true", help="get server config")
    parser.add_argument("--get-sessions", action="store_true", help="list current C2 sessions")
    parser.add_argument("--set-port", default="9999", metavar=('PORT'), help="set the c2 server API port (default 9999)")
    parser.add_argument("--get-session", metavar=('SESSIONID'), help="get detailed info for a session specified by SESSIONID")
    parser.add_argument("--del-session", metavar=('SESSIONID'), help="delete session from C2 server as specified by SESSIONID")
    parser.add_argument("--get-task", metavar=('SESSIONID'), help="get current task from session as specified by SESSIONID")
    parser.add_argument("--set-task", nargs=2, metavar=('SESSIONID', 'COMMAND'), help="set a task for a session as specified by SESSIONID")
    parser.add_argument("--del-task", metavar=('SESSIONID'), help="delete a task from a session as specified by SESSIONID")
    parser.add_argument("--get-output", metavar=('SESSIONID'), help="get task output from a session as specified by SESSIONID")
    parser.add_argument("--del-output", metavar=('SESSIONID'), help="delete task output from a session as specified by SESSIONID")
    parser.add_argument("--get-bootstrap-task", metavar=('HANDLER'), help="get current bootstrap task for new sessions for the specified handler")
    parser.add_argument("--set-bootstrap-task", nargs=2, metavar=('HANDLER', 'COMMAND'), help="set a bootstrap task for new sessions for the specified handler")
    parser.add_argument("--del-bootstrap-task", metavar=('HANDLER'), help="delete a bootstrap task for new sessions for the specified handler")
    parser.add_argument("--set-and-complete-task", nargs=2, metavar=('SESSIONID', 'COMMAND'), 
                        help="set a task for a session as specified by SESSIONID, wait for the command to finish, and then return the output.")
    parser.add_argument("--task-wait-timeout", default=120, metavar=('TIMEOUT'), 
                        help="number of seconds to wait for the command to finish (default 120 seconds). Only used with --set-and-complete-task.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Toggle verbose standard output")
    args = parser.parse_args()
    
    if args.verbose:
        global VERBOSE_OUTPUT
        VERBOSE_OUTPUT = True

    if args.get_version:
        get_server_version(args.set_port)

    elif args.get_config:
        get_server_config(args.set_port)

    elif args.get_sessions:
        get_implant_sessions(args.set_port)

    elif args.get_session:
        guid = args.get_session
        get_session_by_guid(guid, args.set_port)

    elif args.del_session:
        guid = args.del_session
        delete_session(guid, args.set_port)

    elif args.get_task:
        guid = args.get_task
        get_task_by_session_id(guid, args.set_port)

    elif args.set_task:
        guid, task = args.set_task
        set_task_by_session_id(guid, task, args.set_port)

    elif args.del_task:
        guid = args.del_task
        delete_task_by_session_id(guid, args.set_port)

    elif args.get_output:
        guid = args.get_output
        get_task_output_by_session_id(guid, args.set_port)

    elif args.del_output:
        guid = args.del_output
        delete_task_output_by_session_id(guid, args.set_port)
    
    elif args.get_bootstrap_task:
        handler = args.get_bootstrap_task
        get_bootstrap_task(handler, args.set_port)

    elif args.set_bootstrap_task:
        handler, task = args.set_bootstrap_task
        set_bootstrap_task(handler, task, args.set_port)

    elif args.del_bootstrap_task:
        handler = args.del_bootstrap_task
        delete_bootstrap_task(handler, args.set_port)
        
    elif args.set_and_complete_task:
        session_guid, command = args.set_and_complete_task
        timeout = 120
        if args.task_wait_timeout:
            timeout = int(args.task_wait_timeout)
        set_and_complete_task(session_guid, command, args.set_port, timeout)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
