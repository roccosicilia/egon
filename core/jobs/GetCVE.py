###################################################################################################
#
# Get CVE data from NIST
# Author: Rocco <Sheliak> Sicilia - https://roccosicilia.com
# Usage: $ 
#
###################################################################################################

import sys
import json
import requests
import time
import config as cfg
import mysql.connector

# base setup
mydb = mysql.connector.connect(host=cfg.db["host"], user=cfg.db["username"], password=cfg.db["password"], database=cfg.db["database"])
mycursor = mydb.cursor()


cvelist = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0/")
cvelist = json.loads(cvelist.text)
# print(cvelist["result"]["CVE_Items"])

for CVE_Item in cvelist["result"]["CVE_Items"]:
    #print(CVE_Item["cve"]["CVE_data_meta"])
    cveid = CVE_Item["cve"]["CVE_data_meta"]["ID"]
    query_addcve = "INSERT INTO cve_list (cveid) VALUES ({})".format(cveid)
    mycursor.execute(query_addcve)
    mydb.commit()
