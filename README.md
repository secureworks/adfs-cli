## Synopsis

This repo provides tools for creating and managing AWS Tokens via ADFS/SAML.  The installer will also setup dependencies required to utilize the AWS CLI and API.

## Installation

Place files/adfs and files/aws-list into an appropriate bin.

The requirements for this are:
* EL7
* ADFS Setup and enabled for AWS Webservices (URL will be asked for in the init)
* Python requirements in requirements.txt

Notes:
* The first time the adfs is ran, it will build your ini file by default.
* It will ask for ADFS URL which generally looks like this:
  * https://adfs.internal.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices
* Username requires domain ex: domain\user

## Tool Usage

```
$ adfs --help
usage: adfs [-h] [-i] [-R] [-c CONFIG][-C]
               [-r ROLES [ROLES ...]]

optional arguments:
  -h, --help            show this help message and exit
  -i, --init            Generate tokens for all roles
  -R, --refresh         Refresh roles
  						**Does not support multiple ADFS Servers**
  -c CONFIG, --config CONFIG
                        The adfs config file to read
  -C, --create-config   Initialize an ADFS config file
  -r ROLES [ROLES ...], --roles ROLES [ROLES ...]
                        List of roles - only valid with the refresh verb
                        ("adfs.py -r role1 role2 role3")


$ aws-list [alias]
```
## Contributors

Originators: Zach Morgan, Denny Pruitt

Maintainers: Secureworks

Contributors: 
