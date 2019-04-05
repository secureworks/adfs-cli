#!/usr/bin/env python
################################################################################
#  Title:   aws-list
#  Author:  Denny Pruitt <dpruitt@secureworks.com>
#  Date:    Mon Jan 31 13:14:37 EST 2017
#  Version: 0.1
#  Arch:    Linux
#  Descr:   List existing credential data built via adfs
#  Ex:      ./aws-list
################################################################################
#   CHANGELOG
#   Mon Jan 31 13:14:15 EST 2017; 0.1 ; Denny Pruitt <dpruitt@secureworks.com>
#        - Initial Import
################################################################################

import sys
import ConfigParser
import subprocess
from os.path import isfile
from os.path import expanduser

## Initialize Config File

awsconfigfile = '/.aws/credentials'
home = expanduser("~")
filename = home + awsconfigfile
config = ConfigParser.RawConfigParser()
config.read(filename)

def usage():
    print "Usage: aws-list [alias 1] [alias 2] ... [alias n]"

if not isfile(filename):
    print 'Error: {0} file not populated'.format(filename)
    usage()
    sys.exit(1)

def process_date(l_date):
    cmd="date -d "+l_date+" +%s"
    expdate = int(subprocess.check_output(cmd,shell=True))
    curdate = int(subprocess.check_output("date +%s",shell=True))
    if expdate < curdate:
        expire = "Expired"
    else:
        expdate = str(expdate - curdate)
        cmd = "date -d@"+expdate+" -u +%H:%M:%S"
        expdate = (subprocess.check_output(cmd,shell=True)).rstrip()
        expire = "Expires in "+expdate

    return expire

print "Configured Token Status"

if len(sys.argv) > 1:
    refresh = True
    for i in range(len(sys.argv)):
        if i > 0:
            if not config.has_section(sys.argv[i]):
                print 'Error: Alias {0} not defined in config file'.format(sys.argv[i])
                usage()
                sys.exit(1)

            else:
                timeout = config.get(sys.argv[i], 'aws_token_timeout')
                expire = process_date(timeout)
                print '--------'
                print 'Alias:   {0}'.format(sys.argv[i])
                print 'Timeout: {0}'.format(expire)
                print 'ARNs:    {0}'.format(config.get(sys.argv[i], 'arns'))
                print 'Act Num: {0}'.format(config.get(sys.argv[i], 'account_number'))



else:
    for sec in config.sections():
        if not sec == 'default':
            timeout = config.get(sec, 'aws_token_timeout')
            expire = process_date(timeout)
            print '--------'
            print 'Alias:   {0}'.format(sec)
            print 'Timeout: {0}'.format(expire)
            print 'ARNs:    {0}'.format(config.get(sec, 'arns'))
            print 'Act Num: {0}'.format(config.get(sec, 'account_number'))

print '--------'
