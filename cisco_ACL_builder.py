#!/usr/bin/env python

import sys
import subprocess
import re
from datetime import datetime

websites = ""
firewall_data = []
failed_urls = []
private_subnets_tcp = 'permit tcp any 10.0.0.0 0.255.255.255\npermit tcp any 172.16.0.0 0.0.255.255\npermit tcp any 192.168.0.0 0.0.255.255\n'
private_subnets_udp = 'permit udp any 10.0.0.0 0.255.255.255\npermit udp any 172.16.0.0 0.0.255.255\npermit udp any 192.168.0.0 0.0.255.255\n'
def DOC_OPEN ():
    global websites
    with open(doc_input, 'r') as sites:
       websites = sites.read().splitlines(True)


def NSLOOKUP(input_urls): #Look websites up and create a dictionary.
    try:
        nslookup_command = f'nslookup {input_urls}'
        lookup_output = subprocess.run(nslookup_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        x = lookup_output.stdout
        b = ",".join(x.split())
        y = b.split(",")
        dict_output = {}
        dict_output.update({y[5]: y[7:]})
        print(dict_output)
        return dict_output
    except:
        #print(lookup_output.stderr)
        pass


def ITERATE_URLS(): #loop through URLS to build a dictionary and append to make list of dictionaries
    for urls in websites:
        dict_updater = NSLOOKUP(urls)
        firewall_data.append(dict_updater)
    return firewall_data

def CREATE_IPV4_FIRWALL_RULE(input_data):  # create Cisco ACL deny config for each URL IP's.
    global doc_output
    four_accesslist_number = 100
    ts = datetime.now().strftime("%d-%m-%Y")
    doc_ouput = (f'{doc_input}_{ts}')
    with open(doc_ouput, "a") as myfile:
        myfile.write(f"\n ######### IPV4 ########\n\n")
        myfile.write(f"ip access-list extended {ipv4_acl_name}\n")
        myfile.write(private_subnets_tcp)
        myfile.write(private_subnets_udp)
        pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")  # regex for all IPv4
        for domains in input_data:
            if domains != None:
                for key, ips in domains.items():
                    four_accesslist_number += 5
                    if key != "request": #scrub non-IP data from filtered list
                        remark = f'remark  #### {key} ####'
                        myfile.write(f"{remark}\n")
                        for entries in ips:
                            if re.match(pattern, entries):
                                permit_tcp = f'permit tcp any host {entries}'
                                permit_udp = f'permit udp any host {entries}'
                                myfile.write(f"{permit_tcp}\n{permit_udp}\n")
                    else:
                        pass
            else:
                pass
        myfile.write(f"deny tcp any any\n")
        myfile.close()


def CREATE_IPV6_FIRWALL_RULE(input_data):  # create Cisco ACL deny config for each URL IP's.
    global doc_output
    four_accesslist_number = 100
    ts = datetime.now().strftime("%d-%m-%Y")
    doc_ouput = (f'{doc_input}_{ts}')
    with open(doc_ouput, "a") as myfile:
        myfile.write(f"\n ######### IPV6 ########\n\n")
        myfile.write(f"ip access-list extended {ipv6_acl_name}\n")
        pattern = re.compile(r'^[0-9a-f:]+$')  # regex for all IPv6
        for domains in input_data:
            if domains != None:
                for key, ips in domains.items():
                    four_accesslist_number += 5
                    if key != "request": #scrub non-IP data from filtered list
                        remark = f'remark  ### {key} ####'
                        myfile.write(f"{remark}\n")
                        for entries in ips:
                            if re.match(pattern, entries):
                                deny = f'permit tcp any host {entries}'
                                myfile.write(f"{deny}\n")
                    else:
                        pass
            else:
                pass
        myfile.write(f"deny tcp any any\n")
        myfile.close()

def main():
    global doc_input
    global ipv4_acl_name
    global ipv6_acl_name
    doc_input = (sys.argv[1])
    ipv4_acl_name = input('Enter a name for the IPv4 ACL: ')
    ipv6_acl_name = input('Enter a name for the IPv6 ACL: ')
    DOC_OPEN()
    ITERATE_URLS()
    CREATE_IPV4_FIRWALL_RULE(firewall_data)
    CREATE_IPV6_FIRWALL_RULE(firewall_data)


main()
