#!/usr/bin/env python
################################################################################
#  Title:   adfs
#  Author:  Denny Pruitt <dpruitt@secureworks.com> and Zach Morgan <zmorgan@secureworks.com>
#    based on work by Quint van Deman <https://www.linkedin.com/in/quint/van/deman-807b86>
#  Date:    Mon Jan 30 13:14:37 EST 2017
#  Version: 0.1
#  Arch:    Linux
#  Descr:   Automate refreshing AWS credentials via ADFS
#  Ex:      ./adfs -h
################################################################################
#   CHANGELOG
#   Tue Jan 31 16:26:52 EST 2017; 0.2 ; Zach Morgan <zmorgan@secureworks.com>
#        - Updated for ADFS 3
#   Mon Jan 30 13:14:15 EST 2017; 0.1 ; Zach Morgan <zmorgan@secureworks.com>
#        - Initial Import
################################################################################

import sys, getopt, base64, argparse, re, os
import requests, getpass, ConfigParser, io, stat
import boto.sts, boto.s3, boto.iam
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from urlparse import urlparse, urlunparse
from requests_ntlm import HttpNtlmAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppressing the SSL errors associated with Wonky SSL Stuff
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Boilerplate to read the ADFS config from file
# `filename` is defined by command line argument or defaults to ./adfs.ini
def read_config(filename):
  global config
  config = ConfigParser.RawConfigParser()
  config.read(filename)
  if not config.has_section('config'):
    print 'Error: unable to open configuration file adfs.ini'
    raise

# Boilerplate to read the AWS credentials from file
# `filename` is defined in the configuration file or command line
def read_credential(filename):
  global credential
  credential = ConfigParser.RawConfigParser()
  credential.read(filename)
  if not credential.has_section('default'):
    generate_default_credential(filename)
    read_credential(filename)

# Takes a ConfigParser object and writes it to file
def write_config(filename, config):
  with open(filename, 'w+') as config_file:
    config.write(config_file)

# Writes a generic AWS credential file
def generate_default_credential(filename):
  with open(filename, 'w') as file:
    file.write("""[default]
output = json
region = us-east-1
aws_access_key_id =
aws_secret_access_key =
""")

# Takes a list of roles from the command line and verifies there are entries
# in the credential file
def validate_roles(roles):
  for role in range(len(roles)):
    if role > 0:
      if not credential.has_section(roles[role]):
        print 'Error: Alias {0} not defined in config file'.format(roles[role])
        raise

def parse_saml2(assertion):
  global awsroles
  awsroles = []
  root = ET.fromstring(base64.b64decode(assertion))
  # Parse the returned assertion and extract the authorized roles
  for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
      for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
        awsroles.append(saml2attributevalue.text)

  for awsrole in awsroles:
    chunks = awsrole.split(',')
    if 'saml-provider' in chunks[0]:
      newawsrole = chunks[1] + ',' + chunks[0]
      index = awsroles.index(awsrole)
      awsroles.insert(index, newawsrole)
      awsroles.remove(awsrole)

def parse_saml3(soup, session, payload):
  for form_tag in soup.find_all('form'):
    action = form_tag.get('action')
    login_id = form_tag.get('id')
    if action:
      if login_id == 'loginForm':
        parsed_url = urlparse(config.get('config', 'idpentryurl'))
        idpauthformsubmiturl = parsed_url.scheme + '://' + parsed_url.netloc + action

  response = session.post(idpauthformsubmiturl, data=payload, verify=False)
  soup = BeautifulSoup(response.text.decode('utf8'), 'html.parser')
  for input_tag in soup.find_all('input'):
    if input_tag.get('name') == 'SAMLResponse':
      global assertion
      assertion = input_tag.get('value')
      parse_saml2(assertion)

# This is kind of a heavy handed approach to filling the form.
# The user field can be called uSeRnaMe etc, or it might be called "email address"
# To make things more interesting, hidden form fields contain sensitive data
# and must be caught by the final `else`
def build_payload(input_tag, payload, username, password):
  name = input_tag.get('name', '')
  value = input_tag.get('value', '')
  if 'user' in name.lower():
    payload[name] = username
  elif 'email' in name.lower():
    payload[name] = username
  elif 'pass' in name.lower():
    payload[name] = password
  else:
    payload[name] = value
  return payload

def saml_response(tag):
  if tag.get('name') == 'SAMLResponse':
    return tag

# Takes a user/pass combo and executes an HTTP request to the SAML entrypoint
# Returns the requests object.
def read_soup(username, password):
  session = requests.Session()
  session.auth = HttpNtlmAuth(username, password, session)
  response = session.get(config.get('config', 'idpentryurl'), verify=False)
  soup = BeautifulSoup(response.text.decode('utf8'), 'lxml')
  if not soup.find_all(saml_response):
    # SAML3 hoooooo
    payload = {}
    for input_tag in soup.find_all('input'):
      payload = build_payload(input_tag, payload, username, password)

    parse_saml3(soup, session, payload)
  for input_tag in soup.find_all('input'):
    if(input_tag.get('name') == 'SAMLResponse'):
      global assertion
      assertion = input_tag.get('value')
      parse_saml2(assertion)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed unless refreshing
def choose_role():
  print ""
  if len(awsroles) > 1:
    i = 0
    print "Please choose the role you would like to assume:"
    for awsrole in awsroles:
      print '[', i, ']: ', awsrole.split(',')[0]
      i += 1

    print "Selection: ",
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
      print 'Error: You selected an invalid role index, please try again'
      sys.exit(0)

    full_arn = awsroles[int(selectedroleindex)]
    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    try:
      gen_token(role_arn, principal_arn, full_arn)
    except:
      print "Unable to generate token for ARN: {0}".format(role_arn)

  else:
    full_arn = awsroles[0]
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]
    try:
      gen_token(role_arn, principal_arn, full_arn)
    except:
      print "Unable to generate token for ARN: {0}".format(role_arn)
  return

# Takes the split up ARN sections and generates the corresponding authentication token
# Writes the token to the specified AWS credential file
def gen_token(r_arn, p_arn, f_arn, role="Nul"):
  region = credential.get('default', 'region')
  conn = boto.sts.connect_to_region(region)
  token = conn.assume_role_with_saml(r_arn.strip(), p_arn, assertion)
  iamconn = boto.iam.connect_to_region(region,
                     aws_access_key_id=token.credentials.access_key,
                     aws_secret_access_key=token.credentials.secret_key,
                     security_token=token.credentials.session_token)
  global aalias
  account_num = r_arn.split(':')[4]
  if role == "Nul":
    role = r_arn.split('/')[1]
    iamalias = iamconn.get_account_alias()
    aalias = (str(iamalias["list_account_aliases_response"]["list_account_aliases_result"]["account_aliases"][0])+"_"+str(role))
  else:
    aalias = role

  # Put the credentials into a specific profile instead of clobbering
  # the default credentials
  if not credential.has_section(aalias):
    credential.add_section(aalias)

  credential.set(aalias, 'output', config.get('config', 'outputformat'))
  credential.set(aalias, 'region', region)
  credential.set(aalias, 'ARNs', f_arn)
  credential.set(aalias, 'account_number', account_num)
  credential.set(aalias, 'aws_access_key_id', token.credentials.access_key)
  credential.set(aalias, 'aws_secret_access_key', token.credentials.secret_key)
  credential.set(aalias, 'aws_session_token', token.credentials.session_token)
  credential.set(aalias, 'aws_token_timeout', token.credentials.expiration)

  try:
    if config.getboolean('config', 'boto2_support'):
      credential.set(aalias, 'aws_security_token', token.credentials.session_token)
  except ConfigParser.NoOptionError:
    pass

  write_config(aws_config_file, credential)

  print '-----'
  print 'Generated a token for:'
  print 'Alias:      {0}'.format(aalias)
  print 'ARNs:       {0}'.format(f_arn)
  print 'Account#:   {0}'.format(account_num)
  print 'Expiration: {0}'.format(token.credentials.expiration)
  print '-----'
  return

# Takes a list of roles, splits the ARN and passes it to gen_token
# If you have more than one ADFS server - THIS WILL DIE
def refresh_role(roles):
  for i in range(len(roles)):
    full_arn = credential.get(roles[i], 'ARNs')
    role_arn = full_arn.split(',')[0]
    principal_arn = full_arn.split(',')[1]
    credential.remove_section(roles[i])
    try:
      gen_token(role_arn, principal_arn, full_arn, roles[i])
    except:
      print "Unable to generate token for ARN: {0}".format(role_arn)

# Takes the argparse object
# Attempts to read the user/pass from config file, alternately prompting the user
# If args.save is specified, we prompt the user and save the user/pass back to the adfs config file
# Finally, we pass the user/pass into read_soup to retrieve the ADFS XML doc
def retrieve_soup(args):
  if config.has_option('config', 'username'):
    username = config.get('config', 'username')
    password = config.get('config', 'password')
  else:
    print "Username:",
    username = raw_input()
    password = getpass.getpass()
    print ''

  if args.save == True:
    print 'Saving your user/pass to config file in PLAIN TEXT.'
    print 'Danger surely lies ahead! Are you sure? [Y/n]: ',
    response = raw_input().lower()
    if re.match('y', response):
      config.set('config', 'username', username)
      config.set('config', 'password', password)
      write_config(config_file, config)

  response = read_soup(username, password)

  username, password = '#', '#'
  del username
  del password
  return response

# Takes the adfs config filename, and prompts the user to generate a sane config
def generate_default_config(filename):
  print "Output format (ex. 'json'): ",
  outputformat = raw_input()
  print "SSL Verification (ex. True): ",
  sslverification = raw_input()
  print "IDP Entry URL (The IdpInitiatedSignOn.aspx page that you use to log in, including loginToRp query string): ",
  idpentryurl = raw_input()

  boto2_support = False
  print "Enable boto2 backwards compatibility support (True/False) : ",
  if raw_input() in ["True", "true"]:
    boto2_support = True

  config = ConfigParser.RawConfigParser()
  config.add_section('config')
  config.set('config', 'outputformat', outputformat)
  config.set('config', 'sslverification', sslverification)
  config.set('config', 'idpentryurl', idpentryurl)
  config.set('config', 'boto2_support', boto2_support)
  write_config(filename, config)
  os.chmod(filename, stat.S_IREAD|stat.S_IWRITE)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--init', action='store_true',
      help='Generate tokens for all roles')
  parser.add_argument('-R', '--refresh', action='store_true', default=False,
      help='Refresh roles - Does not support multiple ADFS servers')
  parser.add_argument('-c', '--config', default='.aws/adfs.ini',
      help='The adfs config file to read relative to your home directory (ex. ".aws/adfs2.ini")')
  parser.add_argument('-C', '--create-config', action='store_true', default=False,
      help='Initialize an ADFS config file')
  parser.add_argument('-S', '--save', action='store_true', default=False,
      help='Save the user/password provided to the config file')
  parser.add_argument('-r', '--role', nargs='+',
      help='List of roles')
  args = parser.parse_args()

  global config_file
  global aws_config_file
  config_file = os.path.expanduser('~') + '/' + args.config
  aws_config_file = os.path.expanduser('~') + '/.aws/credentials'
  if not os.path.isdir(os.path.expanduser('~') + '/.aws'):
    os.makedirs(os.path.expanduser('~') + '/.aws')

  if args.create_config or not os.path.isfile(config_file):
    generate_default_config(config_file)

  # The way this is written, credentials must always be under the user's home directory
  read_config(config_file)
  read_credential(aws_config_file)

  if not args.init:
    validate_roles

  response = retrieve_soup(args)

  # If the init option is specified we refresh all available roles
  if args.init:
    for role in range(len(awsroles)):
      full_arn = awsroles[role]
      role_arn = awsroles[role].split(',')[0]
      principal_arn = awsroles[role].split(',')[1]

      try:
        gen_token(role_arn, principal_arn, full_arn)
      except:
        print "Unable to generate token for ARN: {0}".format(role_arn)
  # If roles are specified (-r <role> <role>...), we refresh them instead.
  elif args.role:
    if len(args.role) > 0:
      refresh_role(args.role)
  # If the refresh argument is specified, we gather a list of roles from the AWS credentials and refresh them
  elif args.refresh:
    roles = credential.sections()
    roles.remove('default')
    refresh_role(roles)
  # The default action is choose_role(), in which we refresh a single role based on user input
  else:
    choose_role()

if __name__ == '__main__':
  main()
