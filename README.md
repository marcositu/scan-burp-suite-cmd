The propose of this script is scan using the burp-api-api for Burp Suite that will use target files.

For the proper functioning it’s necessary the following tool: https://github.com/vmware/burp-rest-api 

The procedure usage of the script is the following:
- We use as an argument a file with the hosts.
- The script adds each host to spider.
- Once the scan is completed, there are reports in xml and html.
- Then we parse the xml and save the results in SQLite.
- Once each scan is completed is sending the vulnerabilities identified.
- When a scan is finished, an alert message is sent via Telegram specifying the host and the number of identified vulnerabilities

The following variables values must be modified:
- TOKEN
- tb_chatid
- folderrestapi


The scan is running only 1 hour, after 1 hour the scan finishes. If you want to modify the duration time, navigate to::
```
def func_reporte():
  time.sleep(3600)
```
Bear in mind that it may be required to modify the API URL: http://127.0.0.1:8090

Example:

```
# python3 scan-burp-suite-cmd.py domains.txt
```

<img src="https://i.ibb.co/rtpr0HJ/web.png" width="60%" height="60%">
<img src="https://i.ibb.co/M5YQy9J/bot.jpg" width="60%" height="60%">
<img src="https://i.ibb.co/qsmV92P/db.png" width="60%" height="60%">

Sorry about the code, I’m not good developing
