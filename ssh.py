#!/usr/bin/env python2
#
# Python script to SSH connect and run command.
# Dependancies include Paramiko for crypto support

import interactive
import paramiko


paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
ssh.connect(look_for_keys=False, allow_agent=False, hostname='172.16.177.25', port=22, username='jadmin', password='Juniper1@JITC')
chan = ssh.invoke_shell()

#print repr(ssh.get_transport())
print '*** Authenticated'

interactive.interactive_shell(chan)
#ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('show version | display xml')
#type(ssh_stdin)
#type(ssh_stdout)
#ssh_stdout.readlines()
#print ssh_stdin.readlines()
#print ssh_stdout.readlines()
chan.close()
print 'SSH Connection Closed'
ssh.close()