#!/usr/bin/python
## Glen Dosey <doseyg@r-networks.net>
## 2019-01-09
## MIT License
##
import sys, datetime
import whois, json
from elasticsearch import Elasticsearch, helpers
import requests
var = sys.argv[1]

def send_to_elasticsearch(myjson):
	json_string = json.dumps(myjson)
	json_list = []
	json_list.append(json_string)
	es = Elasticsearch('http://elastic:changeme@elk_server:9200')
	helpers.bulk(es,json_list,index='misp_hits', doc_type='generated')

def send_to_splunk(myjson):
	SPLUNK_URI='https://splunk_server:8088/services/collector'
	SPLUNK_KEY="splunk_api_key"
	authHeader={'Authorization': 'Splunk ' + SPLUNK_KEY }
	json_event = { "event": myjson }
	response = requests.post(SPLUNK_URI, headers=authHeader, json=json_event, verify=False)
	result = response.text
	#return result


def load_disk_cache():
	## Initialize the memory cache from the disk cache
	try:
		disk_cache_file = open('whois.cache', 'r') 
		disk_cache_content = disk_cache_file.read()
		disk_cache_json = json.loads(disk_cache_content)
		disk_cache_file.close()
	except:
		disk_cache_json = {}
	#print("DEBUG: DISK CACHE CONTENT:" + disk_cache_content)
	return disk_cache_json

mem_cache = load_disk_cache()

if var in mem_cache.keys():
	print("DEBUG: Mem_Cache hit")
	results = mem_cache[var]
else:
	print("DEBUG: Mem_Cache miss")
	results = whois.whois(var)
	#send_to_elasticsearch(results)
	mem_cache[var] = results

print(results)
disk_cache = open('whois.cache', 'w')  
disk_cache.write(json.dumps(mem_cache, default=str))  
disk_cache.close()
