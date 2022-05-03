#!/usr/bin/python3

import argparse
import pprint
import requests

def get_server_version():
    url = "http://localhost:9999/api/v1.0/version"
    r = requests.get(url)
    print(r.text)


def get_server_config():
    url = "http://localhost:9999/api/v1.0/config"
    r = requests.get(url)
    print(r.text)

def get_implant_sessions():
    url = "http://localhost:9999/api/v1.0/sessions"
    r = requests.get(url)
    pprint.pprint(r.json())

def get_session_by_guid(guid: str):
    url = "http://localhost:9999/api/v1.0/session/" + guid
    r = requests.get(url)
    pprint.pprint(r.json())

def delete_session(guid: str):
    url = "http://localhost:9999/api/v1.0/session/delete/" + guid
    r = requests.delete(url)
    print(r.text)

def get_task(guid: str):
    url = "http://localhost:9999/api/v1.0/task/" + guid
    r = requests.get(url)
    print(r.text)
    

def set_task(guid, task: str):
    url = "http://localhost:9999/api/v1.0/task/" + guid
    r = requests.post(url, task)
    print(r.text)


def delete_task(guid: str):
    url = "http://localhost:9999/api/v1.0/task/" + guid
    r = requests.delete(url)
    print(r.text)

def get_task_output(guid: str):
    url = "http://localhost:9999/api/v1.0/task/output/" + guid
    r = requests.get(url)
    print(r.text)

def delete_task_output(guid: str):
    url = "http://localhost:9999/api/v1.0/task/output/" + guid
    r = requests.delete(url)
    print(r.text)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--get-version", action="store_true", help="get control server version")
    parser.add_argument("--get-config", action="store_true", help="get server config")
    parser.add_argument("--get-sessions", action="store_true", help="list current C2 sessions")
    parser.add_argument("--get-session", help="get detailed info for a session specified by guid")
    parser.add_argument("--del-session", help="delete session from C2 server as specified by guid")
    parser.add_argument("--get-task", help="get current task from session as specified by guid")
    parser.add_argument("--set-task", nargs=2, help="set a task for a session as specified by guid")
    parser.add_argument("--del-task", help="delete a task from a session as specified by guid")
    parser.add_argument("--get-output", help="get task output from a session as specified by guid")
    parser.add_argument("--del-output", help="delete task output from a session as specified by guid")
    args = parser.parse_args()

    if args.get_version:
         get_server_version()

    elif args.get_config:
        get_server_config()

    elif args.get_sessions:
        get_implant_sessions()

    elif args.get_session:
        guid = args.get_session
        get_session_by_guid(guid)

    elif args.del_session:
        guid = args.del_session
        delete_session(guid)

    elif args.get_task:
        guid = args.get_task
        get_task(guid)

    elif args.set_task:
        guid, task = args.set_task
        set_task(guid, task)

    elif args.del_task:
        guid = args.del_task
        delete_task(guid)

    elif args.get_output:
        guid = args.get_output
        get_task_output(guid)

    elif args.del_output:
        guid = args.del_output
        delete_task_output(guid)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()