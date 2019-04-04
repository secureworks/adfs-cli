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

## License

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.