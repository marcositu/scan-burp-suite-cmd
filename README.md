The propose of the script is an scan using the burp-api-api for Burp Suite that will use target files.

The procedure is:
We use as argument a file with the hosts.
The script adds each host to spider.
Once the scan is completed there reports in xml and html.
Then we parse the xml and save the results in SQLite.
Once each scan is completed is sending the vulnerabilities identified.
