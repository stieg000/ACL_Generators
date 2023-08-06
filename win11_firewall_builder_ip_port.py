#!/usr/bin/env python

import sys
from datetime import datetime



def DOC_OPEN ():
    global file_input
    global how_long
    with open(doc_input, 'r') as sites:
        file_input = sites.read().splitlines(True)
        how_long = len(file_input)


def CONVERT_INPUT(data): #convert input to dictionary.#x = data.splitlines()
    z = {}
    for lines in data:
        y = lines.split(":")
        z.update({y[0]: y[1].strip('\n')})
    return z


def CREATE_FIRWALL_RULE(firewall_data):  # create windows powershell firewall blocking commands for each URL IP's.
    global doc_output
    ts = datetime.now().strftime("%d-%m-%Y")
    print(f'{how_long} rules have been built!')
    doc_ouput = (f'{ts}_{doc_input}')
    for ip, port in firewall_data.items():
            y = f"powershell New-NetFirewallRule -DisplayName '{displayname}' -Direction Outbound -RemoteAddress '{ip}' -Protocol TCP -RemotePort {port} -Action Block"
            session = (y.replace("[", "").replace("]", ""))
            with open(doc_ouput, "a") as myfile:
                myfile.write(f"{session}\n")



def main():
    global ip_and_ports
    global doc_input
    global displayname
    doc_input = (sys.argv[1])
    displayname = input('Enter the firewall DisplayName:  ')
    DOC_OPEN()
    ip_and_ports = CONVERT_INPUT(file_input)
    CREATE_FIRWALL_RULE(ip_and_ports)



main()
