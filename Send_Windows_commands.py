#!/usr/bin/env python

import sys
import time
import paramiko
from getpass import getpass as secret

username = "stieg"
password = ''
commands = ''
command_errors = ''
quantity = len(commands)

def DOC_OPEN (doc_input):
    global commands
    with open(doc_input, 'r') as sites:
        commands = sites.read().splitlines(True)


def SEND_COMMANDS(target_computer): #open connection and iterate through commands.
    try:
        print(f'Connecting to {target_computer}')
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target_computer, username=username, password=password)
        for single_command in commands:
            #status =
            stdin, stdout, stderr = client.exec_command(f'{single_command}')
            time.sleep(2)
            output2 = stderr.read().decode()
            print(output2)
    except:
        print("Computer unreachable!")
        pass

def main():
    global target_computer
    global doc_input
    global password
    doc_input = (sys.argv[2])
    DOC_OPEN(doc_input)
    target_computer = (sys.argv[1])
    password = secret('Password: ')
    SEND_COMMANDS(target_computer)
    print(f'All {quantity} commands sent!')


main()