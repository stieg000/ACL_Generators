#!/usr/bin/env python

import textfsm
import re
import json
import subprocess
import logging
import time
from netmiko import ConnectHandler


with open('devices.json') as devices:
    target = json.load(devices)

with open('base_permit_list.txt', 'r') as file:
    command_list_start = file.read().splitlines()

with open('url_list.txt', 'r') as file:
    url_list = file.read().splitlines()


nslookup_template = open('nslookup.textfsm')

ips = set()
new_command_list = []
delete_blocker = ['no ip access-list extended blocker4']

logging.basicConfig(filename='blocker.log', level=logging.INFO,
    format='%(asctime)s"%(levelname)s:%(message)s')



def get_ips(target): #get IP's from URL list using nslookup and append them to the ips set.
    a = 0
    while a != 30: # Loop through each URL multiple times to capture all the rotating IPs
        time.sleep(200/1000)
        a += 1
        command = f'nslookup {target}'
        print(target)
        x = subprocess.run(command, shell=True, text=True, capture_output=True)
        re_table = textfsm.TextFSM(nslookup_template)
        fsm_results = re_table.ParseText(x.stdout)
        print(fsm_results)
        for items in fsm_results:
            ips.add(items[0])


def create_acl(list): #create an access list from the set() ips
    for items in list:
        pattern = re.compile(r'\d+\.\d+\.\d+\.')
        first_3_octets = pattern.findall(items)
        x = f'permit ip any {first_3_octets[0]}0 0.0.0.255'
        #print(x)
        command_list_start.append(x)

def send_commands(): #open connection and iterate through commands.
    try:
        #print(f"Connecting to {target['host']}")
        net_connect = ConnectHandler(**target)
        net_connect.config_mode()
        net_connect.send_config_set(delete_blocker)
        net_connect.config_mode()
        net_connect.send_config_set(command_list_start)
        net_connect.disconnect()
    except:
        logging.WARNING(f"Router unreachable!")


def main():
    num = len(url_list)
    for lines in url_list: #loop through each URL to populate ips set()
        num -= 1
        print(f'There are {num} URLs to process!')
        get_ips(lines)
        # print(ips)
        # print(len(ips))
    create_acl(ips)
    send_commands()
    with open('master_acl.txt', 'w') as document: #overwrite the master_acl.txt file with the newly created access-list
        for lines in command_list_start:
            items = f'{lines}\n'
            document.write(items)
    print(f'{len(ips)} have been found from the URL list.')
    print(f'{len(command_list_start)} ACLs created.')


main()

