#!/usr/bin/env python

import re
import json


with open('amazon.json') as data:
    amazon_data = json.load(data)

cidr_notated_ip = []
conversion_permit_list = []


def extract_ips():
    data = amazon_data['prefixes']
    for item in data:
            try:
                match = 'us'
                region_match = item['region'][:2]
                if region_match == match:
                    a = item['ip_prefix']
                    #print(a)
                    cidr_notated_ip.append(a)
            except:
                pass

def convert_cidr_to_wildcard(data):  #Convert Cidr notation to wildcard masks.
    b = data.split('/')
    prefix_length = int(b[1])

    network_address = b[0]

    if prefix_length == 32:
        wildcard_mask = '0.0.0.0'
    elif prefix_length == 31:
        wildcard_mask = '0.0.0.1'
    elif prefix_length == 30:
        wildcard_mask = '0.0.0.3'
    elif prefix_length == 29:
        wildcard_mask = '0.0.0.7'
    elif prefix_length == 28:
        wildcard_mask = '0.0.0.15'
    elif prefix_length == 27:
        wildcard_mask = '0.0.0.31'
    elif prefix_length == 26:
        wildcard_mask = '0.0.0.63'
    elif prefix_length == 25:
        wildcard_mask = '0.0.0.127'
    elif prefix_length == 24:
        wildcard_mask = '0.0.0.255'
    elif prefix_length == 23:
        wildcard_mask = '0.0.1.255'
    elif prefix_length == 22:
        wildcard_mask = '0.0.3.255'
    elif prefix_length == 21:
        wildcard_mask = '0.0.7.555'
    elif prefix_length == 20:
        wildcard_mask = '0.0.15.255'
    elif prefix_length == 19:
        wildcard_mask = '0.0.31.255'
    elif prefix_length == 18:
        wildcard_mask = '0.0.63.255'
    elif prefix_length == 17:
        wildcard_mask = '0.0.127.255'
    elif prefix_length == 16:
        wildcard_mask = '0.0.255.255'
    elif prefix_length == 15:
        wildcard_mask = '0.1.255.255'
    elif prefix_length == 14:
        wildcard_mask = '0.3.255.255'
    elif prefix_length == 13:
        wildcard_mask = '0.7.255.255'
    elif prefix_length == 12:
        wildcard_mask = '0.15.255.255'
    elif prefix_length == 11:
        wildcard_mask = '0.31.255.255'
    elif prefix_length == 10:
        wildcard_mask = '0.63.255.255'
    elif prefix_length == 9:
        wildcard_mask = '0.127.255.255'
    elif prefix_length == 8:
        wildcard_mask = '0.255.255.255'
    elif prefix_length == 7:
        wildcard_mask = '1.255.255.255'
    elif prefix_length == 6:
        wildcard_mask = '3.255.255.255'
    elif prefix_length == 5:
        wildcard_mask = '7.255.255.255'
    elif prefix_length == 4:
        wildcard_mask = '15.255.255.255'
    elif prefix_length == 3:
        wildcard_mask = '31.255.255.255'
    elif prefix_length == 2:
        wildcard_mask = '63.255.255.255'
    elif prefix_length == 1:
        wildcard_mask = '127.255.255.255'
    else:
        return

    return [network_address, wildcard_mask]

def main():
    extract_ips()
    for item in cidr_notated_ip:
        x = convert_cidr_to_wildcard(item)
        y = f'permit ip any {x[0]} {x[1]}'
        conversion_permit_list.append(y)
    with open('amazon_acl_list.txt','w') as document:# overwrite the master_acl.txt file with the newly created access-list
        for entry in conversion_permit_list:
            newline = f'{entry}\n'
            document.write(newline)
    acls_created = (len(conversion_permit_list))
    print(f'{acls_created} have been created!')





main()