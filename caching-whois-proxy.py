#!/usr/bin/python
import sys, datetime
## This is the python-whois package; pip install python-whois
import whois
from elasticsearch import Elasticsearch, helpers
import requests, json
from urlparse import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer


class webHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		try:
			if self.path=="/":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = '<html><body>Submit your Whois query<br><form action="/api"><input type="text" name="query"><br><input type="submit"></form></body></html>'
				self.wfile.write(html)
			elif self.path.startswith("/api?query"):
				query = urlparse(self.path).query
				query_args = dict(args.split("=") for args in query.split("&"))
				question = query_args['query']
				answer = whois_lookup(question)
				self.send_response(200)
				self.send_header('Content-type','text/json')
				self.end_headers()
				self.wfile.write(json.dumps(answer,indent=4, sort_keys=True, default=str))

			elif self.path.startswith("/api?cache"):
				query = urlparse(self.path).query
				query_args = dict(args.split("=") for args in query.split("&"))
				whois_query = query_args['cache']
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = 'success'
				self.wfile.write(html)
			else:
				self.send_error(404,'Something went wrong. Query was: %s' % self.path)
			return
		except Exception as e:
			self.send_error(500,'Something went wrong. Query was: %s' % e)

	def do_POST(self):
		self.send_error(404,'Something went wrong. You can\'t Post to this site. ')
		return



def send_to_elasticsearch(args,myjson):
	json_string = json.dumps(myjson['_source'])
	json_list = []
	json_list.append(json_string)
	es = Elasticsearch('http://elastic:changeme@elk_server:9200')
	helpers.bulk(es,json_list,index='whois_cache', doc_type='generated')

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

#mem_cache = {}


def whois_lookup(question):
	if question in mem_cache.keys():
		print("DEBUG: Mem_Cache hit")
		results = mem_cache[question]
	else:
		print("DEBUG: Mem_Cache miss")
		results = whois.whois(question)
		#send_to_elasticsearch(results)
		mem_cache[question] = results
	disk_cache = open('whois.cache', 'w')  
	disk_cache.write(json.dumps(mem_cache, default=str))  
	disk_cache.close()
	return results



var = sys.argv[1]
mem_cache = load_disk_cache()

if var == '-d':
	## Run the web server, I'll figure out how to background later
	web_port=8080
	server = HTTPServer(('', web_port), webHandler)
	print 'Started httpserver on port ' , web_port
	server.serve_forever()
else:
	## looks like run from command line
	answer = whois_lookup(var)
	print(answer)