#!/usr/bin/python
## Glen Dosey <doseyg@r-networks.net>
## 2019-01-09
## MIT License
## Copyright (c) 2018 Glen Dosey
## caching-whois-proxy.py 
## https://github.com/doseyg/caching-whois-proxy

import sys, datetime
## This is the python-whois package; pip install python-whois
import whois
from elasticsearch import Elasticsearch, helpers
import requests, json
import socket, threading, datetime, syslog
from urlparse import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

## Global variables
## How long to cache a record before asking again, in days. Applies to all cache types
cache_max_age=7
## Port to run web server on
web_port=80
use_mem_cache=True
## Maximum amount of memory to use for cache. Total script usage will exceed this.
mem_cache_max_size=102400

## Store the cache in a file on disk to preload when restarting. Use with mem_cache
use_disk_cache=True
## File to store disk_cache in
disk_cache_filename = "/tmp/whois.cache"
## How often to write mem_cache to disk, in minutes
disk_cache_write_interval=5

## Use elasticsearch to store the cache
use_elasticsearch_cache=False
#use_syslog=True
## only use cached references, do not send whois queries. 
only_use_cache=False

class webHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		try:
			if self.path=="/":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = '<html><body>Submit your Whois query<br><form action="/api"><input type="text" name="query"><br><input type="submit"></form><a href="/stats">Stats</a></body></html>'
				self.wfile.write(html)
			elif self.path=="/stats":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				## Calculate some stats, some day there will be pretty ASCII graphs
				mem_cache_size = sum([sys.getsizeof(v) for v in mem_cache.values()])
				mem_cache_size += sum([sys.getsizeof(k) for k in mem_cache.keys()])
				html = '<html><body><h2>Proxy Cache Stats</h2><br>Total Queries: ' + str(stats['total_queries']) 
				html += '<br>Mem_Cache Hits: ' + str(stats['mem_cache_hit'])
				html += '<br>Mem_Cache Records:' + str(len(mem_cache)) + '</body></html>'
				html += '<br>Mem_Cache Bytes:' + str(mem_cache_size) + '</body></html>'
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
			self.send_error(500,'Something went wrong. Error was: %s' % e)

	def do_POST(self):
		self.send_error(404,'Something went wrong. You can not POST to this site. ')
		return



def send_to_elasticsearch(myjson):
	json_string = json.dumps(myjson, default=str)
	json_list = []
	json_list.append(json_string)
	es = Elasticsearch('http://172.16.135.144:9200')
	helpers.bulk(es,json_list,index='whois_cache', doc_type='generated')

def elasticsearch_query(query):
	cache_expire_date = datetime.datetime.now() - datetime.timedelta(days=cache_max_age)
	es = Elasticsearch('http://172.16.135.144:9200')
	body = {
	      "size": 100,
	      "from": 0,
	      "query": {
		 "bool" : {
		    "must": [{
		          "query_string" : {
		                "cache_question" : question
		          }},
		          {"range" : {
		               "cached_on": {
		                   "gt" : cache_expire_age
		               }
		           }
		    }],
		    "must_not":[],
		    "should":[]
		}
	       }
	 }
	print("cache - - Initiating Elasticsearch query: %s" % self.query)
	results = es.search( size=limit, index=whois_cache, body=body, request_timeout=240 )
	return results

def send_to_syslog(myjson):
	syslog_server='127.0.0.1'
	json_string = json.dumps(myjson, default=str)
	syslog.syslog(json_string)


def send_to_splunk(myjson):
	SPLUNK_URI='https://splunk_server:8088/services/collector'
	SPLUNK_KEY="splunk_api_key"
	authHeader={'Authorization': 'Splunk ' + SPLUNK_KEY }
	json_event = { "event": myjson }
	response = requests.post(SPLUNK_URI, headers=authHeader, json=json_event, verify=False)
	result = response.text
	#return result

def manage_mem_cache():
	mem_cache_size = sum([sys.getsizeof(v) for v in mem_cache.values()])
	mem_cache_size += sum([sys.getsizeof(k) for k in mem_cache.keys()])

def load_disk_cache():
	## Initialize the memory cache from the disk cache
	try:
		disk_cache_file_handle = open(disk_cache_filename, 'r') 
		disk_cache_content = disk_cache_file_handle.read()
		disk_cache_json = json.loads(disk_cache_content)
		disk_cache_file_handle.close()
	except:
		disk_cache_json = {}
	#print("DEBUG: DISK CACHE CONTENT:" + disk_cache_content)
	return disk_cache_json
	
def flush_mem_cache_to_disk():
	## If the disk_cache_write_interval time has been exceeded, copy the mem_cache to a file on disk
	disk_cache_flush_expire = datetime.datetime.now() - datetime.timedelta(minutes=disk_cache_write_interval)
	if stats["disk_cache_last_written"] < disk_cache_flush_expire:
		stats["disk_cache_last_written"] = datetime.datetime.now()
		disk_cache_file_handle = open(disk_cache_file_name, 'w')  
		disk_cache_file_handle.write(json.dumps(mem_cache, default=str))  
		disk_cache_file_handle.close()

def handle_whois_client_connection(client_socket,address):
	request = client_socket.recv(1024)
	question = request.rstrip()
	timestamp = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
	print '{} - - [{}]  "WHOIS {}"'.format(address[0],timestamp,question)
	answer=whois_lookup(question)
	text = json.dumps(answer,indent=4, sort_keys=True, default=str)
	#answer='DEBUG'
	client_socket.send(text)
	client_socket.close()

def whois_server():
	## Listen on port 43 for connections from a Whois client
	bind_ip = '0.0.0.0'
	whois_port = 43
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((bind_ip, whois_port))
	server.listen(5)  # max # of open connections
	print 'Started whois listener on port ' , whois_port
	while True:
		client_sock, address = server.accept()
		#print 'Accepted connection from {}:{}'.format(address[0], address[1])
		client_handler = threading.Thread(target=handle_whois_client_connection, args=(client_sock,address) )
		client_handler.start()

def web_server():
	server = HTTPServer(('', web_port), webHandler)
	print 'Started http server on port ' , web_port
	server.serve_forever()

def update_cache(question,results):
	## Add a cached_on entry to the record so we can determine when to age it out
	results['cached_on']=datetime.datetime.now()
	results['cache_question']=question
	if use_elasticsearch_cache == True:
			es_thread = threading.Thread(target=send_to_elasticsearch, args=(results,))
			es_thread.daemon = False
			es_thread.start()
	#send_to_syslog(results)
	mem_cache[question] = results

def query_cache(question):
	## This function is not used yet. code is inline elsewhere
	results = mem_cache[question]
	#results = disk_cache[quesion]
	#results = elasticsearch_query(question)
	## Calculate the cached record timestamp, and the timestamp cache_max_age ago
	cache_expire_date = datetime.datetime.now() - datetime.timedelta(days=cache_max_age)
	## When read in from disk or ELK, this is unicode, when passed from python-whois is datetime 
	if isinstance(results['cached_on'],unicode):
		cache_entry_age = datetime.datetime.strptime(results['cached_on'], '%Y-%m-%d %H:%M:%S.%f')
	else:
		cache_entry_age = results['cached_on']
	## If the cache entry age has exceeded the configured limit, requery and update the cache
	if cache_entry_age < cache_expire_date:
		results = whois.whois(question)
		update_cache(question,results)
	return results

def whois_lookup(question):
	## Wrap the python-whois lookup with a cache
	stats['total_queries'] +=1
	if question in mem_cache.keys():
		timestamp = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
		print ('cache - - [' + timestamp + ']  "' + question + '" "Mem_Cache:hit"')
		stats['mem_cache_hit']+=1
		results = mem_cache[question]
		## Calculate the cached record timestamp, and the timestamp cache_max_age ago
		cache_expire_date = datetime.datetime.now() - datetime.timedelta(days=cache_max_age)
		## When read in from disk or ELK, this is unicode, when passed from python-whois is datetime 
		if isinstance(results['cached_on'],unicode):
			cache_entry_age = datetime.datetime.strptime(results['cached_on'], '%Y-%m-%d %H:%M:%S.%f')
		else:
			cache_entry_age = results['cached_on']
		## If the cache entry age has exceeded the configured limit, requery and update the cache
		if cache_entry_age < cache_expire_date:
			results = whois.whois(question)
			update_cache(question,results)
	else:
		timestamp = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
		print ('cache - - [' + timestamp + ']  "' + question + '" "Mem_Cache:miss"')
		stats['mem_cache_miss']+=1
		results = whois.whois(question)
		update_cache(question,results)
	if use_disk_cache == True:
		flush_mem_cache_to_disk()
	return results



var = sys.argv[1]
load_timestamp = datetime.datetime.now()
stats = {"mem_cache_hit":0,"mem_cache_miss":0,"disk_cache_hit":0,"disk_cache_miss":0,"total_queries":0,"disk_cache_last_written":load_timestamp}
if use_disk_cache == True:
	mem_cache = load_disk_cache()

if var == '-d':
	## Run the Whois network server
	net_thread = threading.Thread(target=whois_server)
	net_thread.daemon = True
	net_thread.start()
	web_server()

else:
	## looks like run from command line
	answer = whois_lookup(var)
	print(answer)
