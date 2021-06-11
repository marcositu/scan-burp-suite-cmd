#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Download: https://github.com/vmware/burp-rest-api

from xml.dom.minidom import parse
import xml.dom.minidom
import sqlite3
import subprocess
import sys
import os
import time
from os import path
import requests
import sqlite3
import base64
from urllib.parse import urlparse
import telebot

if len(sys.argv)==2:
   archivo = sys.argv[1]
   TOKEN = 'xxx' #telegam token
   tb = telebot.TeleBot(TOKEN)
   tb.get_me()
   tb_chatid = "xxx" #telegram chatid
   file1 = open(f"{archivo}", "r")
   lines = file1.readlines()
   folderrestapi = "/home/user/scripts/burp/burp-rest-api/"
   
   print ("Initiating burp-rest-api.sh")
   os.system(f'screen -A -m -d -S screen_burp_api {folderrestapi}burp-rest-api.sh') #Use command SCREEN

   for line in lines:
      domain = line.strip()
      con = sqlite3.connect("issuesburp.db")
      #Nombre de la tabla vulns, columnas (name, host, path, location, confidence, severity)
      cur = con.cursor()
      dominio = urlparse(f"{domain}").netloc
      reporte = dominio


      def func_inicio(): #Inicio la API, Agrego el hosts al Spider
         time.sleep(20)
         print(f"\n[+] Target: {domain}")
         print(f"\t[-] Adding to the scope")
         session = requests.Session()
         headers = {"User-Agent":"curl/7.68.0","Connection":"close","accept":"*/*"}
         response = session.put(f"http://127.0.0.1:8090/burp/target/scope?url={domain}", headers=headers)
         response = session.post(f"http://127.0.0.1:8090/burp/spider?baseUrl={domain}", headers=headers)
         func_spider()
         func_scan()
         func_reporte()
         issues = func_parserreporte()
         func_telegram(issues)


      def func_spider(): #Chequeo si finalizo el spider
         spiderPercentage = getSpiderPercentage()
         while spiderPercentage < 100:
            time.sleep(20)
            ahora = time.strftime("%H:%M:%S")
            print(f"\t{ahora} - The spider continues")
            spiderPercentage = getSpiderPercentage()
                   
    
      def getSpiderPercentage(): #Cargo el status del spider
         response = requests.get('http://127.0.0.1:8090/burp/spider/status')
         jsonResponse = response.json()
         return jsonResponse["spiderPercentage"]


      def func_scan(): #Inicio el SCAN ACTIVO
         print(f"\t[-] Starting SCAN")
         session = requests.Session()
         headers = {"User-Agent":"curl/7.68.0","Connection":"close","accept":"*/*"}
         response = session.post(f"http://127.0.0.1:8090/burp/scanner/scans/active?baseUrl={domain}", headers=headers)


      def func_telegram(issues): #Inicio el SCAN ACTIVO
         print(f"\t[-] Scan finished. A Telegram message will be send.")
         tb.send_message(f"{tb_chatid}",f"Finished the URL scan for: {domain}") 
         tb.send_message(f"{tb_chatid}", "Number of identified vulnerabilities: " + str(issues))

      def func_reporte():
         time.sleep(3600) #1 hour
         print(f"\t[-] Downloading reports")

         reporte_url_xml = f"http://127.0.0.1:8090/burp/report?reportType=XML&urlPrefix={domain}"
         reporte_url_xml_file = f"{reporte}.xml"
         data = requests.get(reporte_url_xml)
         with open(reporte_url_xml_file, 'wb')as file:
            file.write(data.content)

         reporte_url_html = f"http://127.0.0.1:8090/burp/report?reportType=HTML&urlPrefix={domain}"
         reporte_url_html_file = f"{reporte}.html"
         data = requests.get(reporte_url_html)
         with open(reporte_url_html_file, 'wb')as file:
            file.write(data.content)


      def func_parserreporte(): 
         print(f"\t[-] Writing issues on DB")
         DOMTree = xml.dom.minidom.parse(f"{reporte}.xml")
         issues = DOMTree.documentElement
         vulns = issues.getElementsByTagName("issue")
         cont_issue = 0
         for issue in vulns:
            #print ("*****Issues*****")
            name = issue.getElementsByTagName('name')[0]
            #print ("Name: %s" % name.childNodes[0].data)
            host = issue.getElementsByTagName('host')[0]
            #print ("Host: %s" % host.childNodes[0].data)
            path = issue.getElementsByTagName('path')[0]
            #print ("Path: %s" % path.childNodes[0].data)
            confidence = issue.getElementsByTagName('confidence')[0]
            #print ("Confidence: %s" % confidence.childNodes[0].data)
            severity = issue.getElementsByTagName('severity')[0]
            if len(issue.getElementsByTagName('request')) > 0:
               request = issue.getElementsByTagName('request')[0]
               requestStr = request.childNodes[0].data
               requestxt = base64.b64decode(requestStr).decode('ascii')
               cont_issue += 1

            else:
               requestxt = ""              
            
            con.execute("INSERT INTO vulns (name, host, path, confidence, severity, request) VALUES (?, ?, ?, ?, ?, ?)", (name.childNodes[0].data, host.childNodes[0].data, path.childNodes[0].data, confidence.childNodes[0].data, severity.childNodes[0].data, requestxt))
            con.commit()
         print (f"\t\tNumber of identified vulnerabilities: {cont_issue}") 
         return cont_issue
         
      func_inicio()

else:
   print ("Uso: " + sys.argv[0] + " domains.txt")
