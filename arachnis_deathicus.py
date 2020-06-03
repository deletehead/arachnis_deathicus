#!/usr/bin/env python3
from __future__ import division
from __future__ import print_function
import argparse
import sys, time, cmd, os, ntpath
try:
    from six import PY2
    from impacket.dcerpc.v5 import samr, transport, srvs
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket import LOG
    from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
        FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
    from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY
except:
    print('[!] Import error! Try: pip3 install -r requirements.txt')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', type=str, help='')
    parser.add_argument('-d', '--domain', help="Target _EMAIL_ domain, ex. taylorguitars.com. Be aware this is different than Scylla which refers to Domain as the source of the leak.")
    parser.add_argument('-u', '--username', help="Username")
    parser.add_argument('-p', '--password', help="Password")
    parser.add_argument('-o', '--output', help="Stores ALL output in file. Ex. -o output.json")
    parser.add_argument('-v', '--verbose', action='store_true', help="Prints ALL results to stdout")


if __name__ == '__main__':
    main()
