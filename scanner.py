#!/usr/bin/python  
#Done By: Davonne Beckford
#Email: davonne.development@gmail.com

"""
The scanner will scan all ports between the range specified in the system arguments to see which is open and then
return the banner and service vunerabilities.

Please note all vunerabilities have been defined in the json file
"""

import socket  
import sys  
import os  
import json

HOST = sys.argv[1]
PORT_N_LIST = []

def jsonData(x):
    with open("cve.json") as f:
        data = json.load(f)
    print("The service vunerabilties for the IP {0} on port {1}".format(sys.argv[1],x))
    for d in range(0,len(data)):
        if(data[d]["port"] == x):
            print(data[d]["cve_code"])
            print("The service name is {0}".format(data[d]["service_name"]))

def bannerGrabber(ip_addr,port):
    try:
        socket.setdefaulttimeout(1)
        s = socket.socket()
        s.connect((ip_addr,port))
        msg = 'GET / HTTP/1.1\r\n\r\n'.encode()
        s.sendall(msg)
        banner = s.recv(1024).decode()
        jsonData(port)
        print("The Banner is:")
        print(" ")
        print(banner)
        s.close()
    except:
        print("Error on recieving")
        
def portScanner(ip,portx):
    try:
        socket.setdefaulttimeout(1)
        s = socket.socket()
        c = s.connect((ip,portx))
        j = 'GET / HTTP/1.1\r\n\r\n'.encode()
        m = s.sendall(j)
        rc = s.recvfrom(1024)
        if(rc):
            PORT_N_LIST.append(portx)
            print("Port '{0}' is Opened".format(portx))
    except:
        return (" Port '{0}' has a problem establishing Connection".format(portx))

def runBannerGrabber(ip):
    for open_port in PORT_N_LIST:
        bannerGrabber(ip,open_port)

def portLoop(ip):
    for port in range(int(sys.argv[2]),int(sys.argv[3])):
        print(portScanner(ip,port))

def main(ip):
    if(len(sys.argv[1].split(".")) < 4):
        print("Please enter a valid IP address")
    else:
        portLoop(sys.argv[1])

    print("These are the list of open ports on IP {0} that {1}".format(sys.argv[1],PORT_N_LIST))
    runBannerGrabber(sys.argv[1])


if __name__ == "__main__":
    if(int(sys.argv[2]) > int(sys.argv[3])):
        print("The first port number for must be larger than the second entered")
    elif(int(sys.argv[2]) < int(sys.argv[3])):
        main(sys.argv[1])
    else:
        print("you")

    #72.21.91.29 
    #67.202.92.15
    #172.217.204.189
    #109.73.238.75
