The propose of the script is an scan using the burp-api-api for Burp Suite that will use target files.

For the proper functioning it’s necessary the following tool: https://github.com/vmware/burp-rest-api 

The procedure is:
- We use as argument a file with the hosts.
- The script adds each host to spider.
- Once the scan is completed there reports in xml and html.
- Then we parse the xml and save the results in SQLite.
- Once each scan is completed is sending the vulnerabilities identified.
- When a scan is finished, an alert message is sent via Telegram specifying the host and the number of identified vulnerabilities

The following variables' values must be modified:
- TOKEN
- tb_chatid
- folderrestapi

Bear in mind that it may be required to modify the API URL: http://127.0.0.1:8090

Sorry about the code, I’m not good developing
