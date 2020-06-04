# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Mini shell using some of the SMB funcionality of the library
#
# Author:
#  Alberto Solino (@agsolino)
#
#
# Reference for:
#  SMB DCE/RPC
#
from __future__ import division
from __future__ import print_function
import sys
import time
import cmd
import os
import ntpath

from six import PY2
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket import LOG
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY


# If you wanna have readline like functionality in Windows, install pyreadline
try:
  import pyreadline as readline
except ImportError:
  import readline

class spee_ider(cmd.Cmd):
    def __init__(self, smbClient, depth=3):
        cmd.Cmd.__init__(self)
        self.shell = None

        self.prompt = '# '
        self.smb = smbClient
        self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.depth=depth

    def spee_ider_host(self):
        print('[*] Spidering Shares with depth '+str(self.depth))
        try:
            self.get_info()
        except:
            print('[-] Not enough privs to get info...')
        shares = self.get_shares()
        for i in range(len(shares)):
            share = shares[i]['shi1_netname'][:-1]
            if share != 'C$' and share != 'ADMIN$' and share != 'IPC$':
                try:
                    self.share = share
                    self.tid = self.smb.connectTree(share)
                    self.pwd = '\\'
                    print('[+] Access Granted: '+share)
                    self.ls_main(share)
                except:
                    print('[-] Access Denied: '+share)
                    continue 
            

    def emptyline(self):
        pass

    def precmd(self,line):
        # switch to unicode
        if PY2:
            return line.decode('utf-8')
        return line

    def onecmd(self,s):
        retVal = False
        try:
           retVal = cmd.Cmd.onecmd(self,s)
        except Exception as e:
           LOG.error(e)
           LOG.debug('Exception info', exc_info=True)

        return retVal

    def do_exit(self,line):
        if self.shell is not None:
            self.shell.close()
        return True

    def do_logoff(self, line):
        if self.smb is None:
            LOG.error("No connection open")
            return
        self.smb.logoff()
        del self.smb
        self.share = None
        self.smb = None
        self.tid = None
        self.pwd = ''
        self.loggedIn = False
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = None

    def get_info(self):
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrServerGetInfo(dce, 102)

        print("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
        print("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
        print("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
        print("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
        print("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
        print("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])

    def get_shares(self):
        shares_list = self.smb.listShares()
        for i in range(len(shares_list)):
            print(shares_list[i]['shi1_netname'][:-1])
        return shares_list

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def do_cd(self, line):
        if self.tid is None:
            LOG.error("No share selected")
            return
        p = line.replace('/','\\')
        oldpwd = self.pwd
        if p[0] == '\\':
           self.pwd = line
        else:
           self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE, desiredAccess = FILE_READ_DATA |
                                   FILE_LIST_DIRECTORY, shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE )
            self.smb.closeFile(self.tid,fid)
        except SessionError:
            self.pwd = oldpwd
            raise

    def ls_contents(self, pwd):
        base_dir = pwd.strip('*')
        contents_of_dir = []
        try:
            for f in self.smb.listPath(self.share, pwd):
                if f.get_longname() != '.' and f.get_longname() != '..':
                    print(self.share+base_dir+f.get_longname())
                    if f.is_directory():
                        contents_of_dir.append(f.get_longname())
        except:
            #print('[-] Error listing contents of: '+base_dir)
            pass

        return contents_of_dir

    def ls_main(self, share):
        base_wildcard = '\\*'
        subdirs = self.ls_contents(base_wildcard)
        current_depth = 1
        for subdir in subdirs:
            home_base1 = '\\' + subdir
            pwd = home_base1 + base_wildcard
            sub_subdirs = self.ls_contents(pwd)
            for sub_subdir in sub_subdirs:
                home_base2 = home_base1 + '\\' + sub_subdir
                pwd = home_base2 + base_wildcard
                sub_sub_subdirs = self.ls_contents(pwd)
                for sub_sub_subdir in sub_sub_subdirs:
                    home_base3 = home_base2 + '\\' + sub_sub_subdir
                    pwd = home_base3 + base_wildcard
                    sub_subdirs = self.ls_contents(pwd)

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = line.replace('/','\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return  [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def do_get(self, filename):
        if self.tid is None:
            LOG.error("No share selected")
            return
        filename = filename.replace('/','\\')
        fh = open(ntpath.basename(filename),'wb')
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFile(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

    def do_close(self, line):
        self.do_logoff(line)

    def do_EOF(self, line):
        print('Bye!\n')
        return True
