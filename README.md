The propose of this script is scan using the burp-api-api for Burp Suite that will use target files.

For the proper functioning it’s necessary the following tool: https://github.com/vmware/burp-rest-api and command screen.

The script reads the config.ini file where it is configured:
- folderrestapi = Folder where burp-rest-api is located (e.g. -> /home/user/burp-rest-api/)
- telegrambot = Here you must enter yes (to send notification via telegram) or no
- token = Telegram token (e.g. -> 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11 )
- chatid = Telegram chat id (e.g. -> 11111 )
- downloadreport = Number of seconds to wait before cancelling the scan and downloading the report (e.g. -> 3600) 

The procedure usage of the script is the following:
- We use as an argument a file with the hosts.
- The script adds each host to spider.
- Once the scan is completed, there are reports in xml and html.
- Then we parse the xml and save the results in SQLite.
- Once each scan is completed is sending the vulnerabilities identified.
- When a scan is finished, an alert message is sent via Telegram specifying the host and the number of identified vulnerabilities

Example:

```
# python3 scan-burp-suite-cmd.py domains.txt
```

<img src="https://i.ibb.co/YjScqC4/15.png" width="80%" height="80%">
<img src="https://i.ibb.co/gFFY9Rj/16.png" width="80%" height="80%">
<img src="https://i.ibb.co/2vQRcPN/17.png" width="80%" height="80%">

Sorry about the code, I’m not good developing
