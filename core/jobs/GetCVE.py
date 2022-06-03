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
from datetime import datetime

# base func
def debug(msg):
    now = datetime.now()
    current_time = now.strftime("%Y/%m/%d %H:%M:%S")
    debug_file = open(cfg.log["debug"], 'a')
    debug_file.write("[{}] {}".format(current_time, msg))
    debug_file.close()

# base setup
mydb = mysql.connector.connect(host=cfg.db["host"], user=cfg.db["username"], password=cfg.db["password"], database=cfg.db["database"])
mycursor = mydb.cursor()

try:
    cvelist = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0/")
    cvelist = json.loads(cvelist.text)
    debug("Get CVE list.")
except:
    debug("Error: CVE list non available.")

for CVE_Item in cvelist["result"]["CVE_Items"]:
    cveid = CVE_Item["cve"]["CVE_data_meta"]["ID"]
    query_addcve = "INSERT INTO cve_list (cveid) VALUES ('{}')".format(cveid)
    mycursor.execute(query_addcve)
    mydb.commit()
