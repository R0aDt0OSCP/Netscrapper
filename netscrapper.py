import json
import sys
import os
import subprocess
import shlex
import string
import random

from multiprocessing.pool import ThreadPool
from termcolor import colored, cprint

ip_range = []
hosts = {}
ports = "ports"


def printred(text):
    cprint(text, 'red', attrs=['bold'])
def handle_output():
    # running nmap for exploting the services
    for file in os.listdir('.'):
        if file.endswith(".xml"):
            # Prints only text file present in My Folder
            print(file)
            try:
                with open(file) as json_file:
                    loaded_json = json.load(json_file)
                    for x in loaded_json:
                        ### Parse the open port
                        if x["ports"][0]["status"] == "open":
                            port = x["ports"][0]["port"]
                            ip_addr = x["ip"]
                            ### Add the IP address to dictionary if it doesn't already exist
                            try:
                                hosts[ip_addr]
                            except KeyError:
                                hosts[ip_addr] = {}

                            ### Add the port list to dictionary if it doesn't already exist
                            try:
                                hosts[ip_addr][ports]
                            except KeyError:
                                hosts[ip_addr][ports] = []

                            ## append the port to the list
                            if port in hosts[ip_addr][ports]:
                                pass
                            else:
                                hosts[ip_addr][ports].append(port)

                        # Create host and port scan text file
                    text_file = open("scans.txt", 'w')
                    hcount = 0

                    for h in hosts:
                        port_str = "-p"
                        print("[+] Host: %s" % h)
                        # Write the host
                        text_file.write("%s" % h)
                        hcount += 1
                        for p in hosts[h]["ports"]:
                            print("    [+] Port: %s" % p)
                            blah = str(p)
                            port_str += blah
                            port_str += str(",")
                        tmp_str = port_str[:-1]
                        text_file.write(" %s\n" % tmp_str)
                    print("[+] Created %d scan lines in text file: 'scans.txt'" % hcount)
                    text_file.close()
                   
                    printred(
                        "Command:  while IFS=' ' read -r host ports; do sudo nmap -n -vvv $host $ports -sV -sC -oN $host.txt;done < scans.txt")
                    cmdstr = "while IFS=' ' read -r host ports; do sudo nmap -n -vvv $host $ports -sV -sC -oN $host.txt;done < scans.txt"
                    subprocess.Popen(cmdstr, shell=True).wait()

            except:
                print("Error in reading file")


def running_massscan(ip):
    try:
        if os.geteuid() != 0:  # If not root user...
            print("Exiting...run with sudo")
            exit(0)
        else:
            printred("\n[+] Beginning initial Massscan. This may take a few minutes.\n")
            cmd = "masscan  -Pn  -p 21-9900 " + ip + " --rate 10000 -oJ masscan_" + ''.join(
                random.choices(string.ascii_lowercase +
                               string.digits, k=4)) + ".xml"
            # args = shlex.split(cmd)
            # print(args)
            subprocess.Popen(cmd, shell=True).wait()
            printred("\n[+] Beginning massscan This may take a few minutes.\n")
            handle_output()
    except:
        printred("Error in Running massscan")

    # Do Nothing


# Reading the file having hosts:


with open(sys.argv[1]) as fh:
    for line in fh:
        ip_range.append(line.strip())

# Run 5 multiple threads. Each call will take the next word in wordlist array
results = ThreadPool(5).imap_unordered(running_massscan, ip_range)
for r in results:
    if r is not None:
        print (r)
