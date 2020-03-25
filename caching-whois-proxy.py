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
import requests, json
import socket, threading, datetime, syslog, collections, time
if sys.version_info.major == 2:
	from urlparse import urlparse
	from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
elif sys.version_info.major == 3:
	from urllib.parse import urlparse
	from http.server import BaseHTTPRequestHandler,HTTPServer
	unicode = str
try:
    from elasticsearch import Elasticsearch, helpers
except ImportError:
    print("elasticsearch module not installed; elasticsearch components won't work")

########### Global Configuration variables ################
## How long to cache a record before asking again, in days. Applies to all cache types
cache_max_age=7
## Port to run web server on
enable_web_server=True
web_port=80
use_mem_cache=True
## Maximum amount of memory to use for cache. Total script usage will exceed this.
mem_cache_max_size=102400000

## Store the cache in a file on disk to preload when restarting. Use with mem_cache
use_disk_cache=True
## File to store disk_cache in
disk_cache_filename = "/var/run/whois.cache"
## How often to write mem_cache to disk, in minutes
disk_cache_write_interval=3
logfile = "/var/log/caching-whois-proxy.log"
## Use elasticsearch to store the cache
use_elasticsearch_cache=False
## The elasticsearch server to use, format http://user:pass@hostname:9200
elasticsearch_server='http://127.0.0.1:9200'
## Send a copy of the whois lookup results to syslog 
use_syslog=True
## only use cached references, do not send whois queries. You must side-load the disk_cache or elasticsearch for this to work 
only_use_cache=False
## What value to return if use_only_cache is True, and the question is not in the cache
not_cached_result=None
## How often to allow a new query, in seconds
rate_limit_queries=5
rate_limit_use_backlog=True
rate_limit_backlog_rate=5
rate_limit_backlog_size=1000
###############  No configuration below this line ###########################

def logger(content):
	log=open(logfile,"a")
	log.write(content + "\n")
	log.close()

class webHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		try:
			if self.path=="/":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = '<html><body>Submit your Whois query<br><form action="/api"><input type="text" name="query"><br><input type="submit"></form><a href="/stats">Stats</a></body></html>'
				if sys.version_info.major == 3:
					self.wfile.write(bytes(html, "utf-8"))
				else:
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
				html += '<br>Mem_Cache Records:' + str(len(mem_cache)) 
				html += '<br>Mem_Cache Bytes:' + str(mem_cache_size) 
				html += '<br>Exceeded Rate Limit: ' + str(stats['exceeded_rate_limit'])
				html += '<br>Elasticsearch Hits:' + str(stats['elasticsearch_cache_hit']) + '</body></html>'
				if sys.version_info.major == 3:
					self.wfile.write(bytes(html, "utf-8"))
				else:
					self.wfile.write(html)
			elif self.path=="/config":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = '<html><body><h2>Proxy Cache Config</h2><br>Use_mem_cache: ' + str(use_mem_cache) 
				html += '<br>Mem_Cache Max Size: ' + str(mem_cache_max_size)
				html += '<br>Cache Max Age:' + str(cache_max_age) 
				html += '<br>rate_limit_queries:' + str(rate_limit_queries) 
				html += '<br>Elasticsearch Hits:' + str(stats['elasticsearch_cache_hit']) + '</body></html>'
				if sys.version_info.major == 3:
					self.wfile.write(bytes(html, "utf-8"))
				else:
					self.wfile.write(html)
			elif self.path=="/api?dump_mem_cache":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = '<html><body><h2>Proxy Memory Cache Contents</h2><br> ' + str(json.dumps(mem_cache, default=str)) + '</body></html>'
				if sys.version_info.major == 3:
					self.wfile.write(bytes(html, "utf-8"))
				else:
					self.wfile.write(html)
			elif self.path.startswith("/api?query"):
				query = urlparse(self.path).query
				#query = urllib.parse.urlparse(self.path).query
				query_args = dict(args.split("=") for args in query.split("&"))
				question = query_args['query']
				answer = whois_lookup(question)
				self.send_response(200)
				self.send_header('Content-type','text/json')
				self.end_headers()
				if sys.version_info.major == 3:
					self.wfile.write(bytes(json.dumps(answer,indent=4, default=str), "utf-8"))
				else:
					self.wfile.write(json.dumps(answer,indent=4, default=str))
			elif self.path.startswith("/api?cache"):
				query = urlparse(self.path).query
				#query = urllib.parse.urlparse(self.path).query
				query_args = dict(args.split("=") for args in query.split("&"))
				question = query_args['cache']
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				html = 'success'
				if sys.version_info.major == 3:
					self.wfile.write(bytes(html, "utf-8"))
				else:
					self.wfile.write(html)
				my_thread = threading.Thread(target=whois_lookup, args=(question,))
				my_thread.start()
			else:
				self.send_error(404,'Something went wrong. Query was: %s' % self.path)
			return
		except Exception as e:
			self.send_error(500,'Something went wrong. Error was: %s' % e)

	def do_POST(self):
		self.send_error(404,'Something went wrong. You can not POST to this site. ')
		return
	def log_message(self,format,*args):
		my_message = self.address_string() + " - - [" + self.log_date_time_string() + "] " + str(args) 
		logger(my_message)



def send_to_elasticsearch(myjson):
	json_string = json.dumps(myjson, default=str)
	json_list = []
	json_list.append(json_string)
	es = Elasticsearch(elasticsearch_server)
	try:
		helpers.bulk(es,json_list,index='whois_cache', doc_type='generated')
	except Exception as e:
		logger("cache - - Failed to perform elasticsearch insert: " + str(e))


def elasticsearch_query(question):
	cache_expire_date = datetime.datetime.now() - datetime.timedelta(days=cache_max_age)
	es = Elasticsearch(elasticsearch_server)
	limit = 1000
	body = {
	      "size": 100,
	      "from": 0,
	      "query": {
		 "bool" : {
		    "must": [{
		          "term" : { "cache_question" : question }},
		          {"range" : { "cached_on": { "gt" : cache_expire_date } }
		    }],
		    "must_not":[],
		    "should":[]
		}
	       }
	 }
	logger("cache - - Initiating Elasticsearch query: %s" % question)
	try:
		results = es.search( size=limit, index='whois_cache', body=body, request_timeout=240 )
	except Exception as e:
		logger("cache - - Failed to perform elasticsearch query")
		results = None
	return results

def send_to_syslog(myjson):
	syslog_server='127.0.0.1'
	json_string = json.dumps(myjson, default=str)
	#syslog.openlog(syslog.LOG_LOCAL4)
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
	## This function removes records from the mem_cache if the mem_cache_max_size is exceeded
	oldest_key = [None, None, None, None, None]
	mem_cache_size = sum([sys.getsizeof(v) for v in mem_cache.values()])
	mem_cache_size += sum([sys.getsizeof(k) for k in mem_cache.keys()])
	if mem_cache_size > mem_cache_max_size:
		for key in mem_cache:
			if oldest_key[0] is None:
				oldest_key[0] = key
			## this sort of works. Its possible the first entry is the oldest, in which case only 1 item is removed instead of 4. 
			elif mem_cache[key]['cached_on'] < mem_cache[oldest_key[0]]['cached_on']:
				oldest_key[4] = oldest_key[3]
				oldest_key[3] = oldest_key[2]
				oldest_key[2] = oldest_key[1]
				oldest_key[1] = oldest_key[0]
				oldest_key[0] = key
		for i in range (0, 4):
			if oldest_key[i] is not None:
				mem_cache.pop(oldest_key[i])
				timestamp = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
				logger('cache - - [' + timestamp + ']  "' + oldest_key[i] + '" "Mem_Cache:purge due to size exceeded"')

def load_disk_cache():
	## Initialize the memory cache from the disk cache
	try:
		disk_cache_file_handle = open(disk_cache_filename, 'r') 
		disk_cache_content = disk_cache_file_handle.read()
		disk_cache_json = json.loads(disk_cache_content)
		##Convert cached_on timestamp from string back to datetime.datetime object
		for key in disk_cache_json:
			if isinstance(disk_cache_json[key]['cached_on'],unicode):
				disk_cache_json[key]['cached_on'] = datetime.datetime.strptime(disk_cache_json[key]['cached_on'], '%Y-%m-%d %H:%M:%S.%f')
		
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
		disk_cache_file_handle = open(disk_cache_filename, 'w')  
		disk_cache_file_handle.write(json.dumps(mem_cache, default=str))  
		disk_cache_file_handle.close()

def handle_whois_client_connection(client_socket,address):
	## This function responds to queries received from whois clients
	request = client_socket.recv(1024)
	question = request.rstrip()
	timestamp = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
	logger(address[0] + ' - - ['+timestamp+']  "WHOIS '+ question)
	answer=whois_lookup(question)
	text = json.dumps(answer,indent=4, sort_keys=False, default=str)
	#answer='DEBUG'
	client_socket.send(text)
	client_socket.close()

def backlog_worker():
	global backlog_questions
	logger("Started backlog thread")
	while(True):
		run=1
		time.sleep(rate_limit_backlog_rate)
		##logger("backlog - - - thread heartbeat")
		try:
			while(run==1):
				question = backlog_questions.popleft()
				if question in mem_cache.keys():
					logger("backlog - - - question found in mem_cache, removing: " + str(question))
					continue
				elif use_elasticsearch_cache == True and query_elasticsearch_cache(question) is not None:
					logger("backlog - - - question found in elastic_cache, removing: " + str(question))
					continue
				else:
					results = query_whois_internet(question)
					logger("backlog - - - queried whois from backlog: " + str(question))
					run=0
		except IndexError as e:
			logger ('backlog - - - Queue is empty: ' + str(e) )
			continue
		except Exception as e:
			logger ('backlog - - - Error in backlog_thread: ' + str(e))
			continue

def whois_server():
	## Listen on port 43 for connections from a Whois client
	bind_ip = '0.0.0.0'
	whois_port = 43
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((bind_ip, whois_port))
	server.listen(5)  # max # of open connections
	logger ('Started whois listener on port ' + str(whois_port))
	while True:
		client_sock, address = server.accept()
		#print 'Accepted connection from {}:{}'.format(address[0], address[1])
		client_handler = threading.Thread(target=handle_whois_client_connection, args=(client_sock,address) )
		client_handler.start()

def web_server():
	## This is just a stub function to call the full web server
	server = HTTPServer(('', web_port), webHandler)
	logger( 'Started http server on port ' + str( web_port))
	server.serve_forever()

def update_cache(question,results):
	## This function updates any configured caches with the question and results 
	## Add a cached_on entry to the record so we can determine when to age it out
	results['cached_on']=datetime.datetime.now()
	results['cache_question']=question
	if use_elasticsearch_cache == True:
			es_thread = threading.Thread(target=send_to_elasticsearch, args=(results,))
			es_thread.daemon = False
			es_thread.start()
	if use_syslog==True:
		send_to_syslog(results)
	mem_cache[question] = results
	## We only need to write the cache to disk and manage it's size if we are adding an entry, so these go here
	if use_disk_cache == True:
		flush_mem_cache_to_disk()
	manage_mem_cache()
	
def json_validator(json_string):
	try:
		json_object = json.loads(json_string)
		return json_string
	except:
		json_string = {}
		return json_string
	
def query_whois_internet(question):
	global rate_limit_timestamp
	global rate_limit_use_backlog
	global backlog_questions
	my_rate = rate_limit_timestamp + datetime.timedelta(seconds=rate_limit_queries)
	if threading.currentThread().getName() == 'backlog_worker':
		my_rate = datetime.datetime.now()
	## This function performs a whois query to the internet, caching results
	if only_use_cache == True:
		results = not_cached_result
		return results
	elif my_rate > datetime.datetime.now() :
		logger("ratelimit - - exceeded configured request interval: " + str(question))
		stats['exceeded_rate_limit']+=1
		if rate_limit_use_backlog == True:
			logger("ratelimit - - adding question to backlog: " + str(question))
			backlog_questions.append(question)
		return None
	else:
                try:
                    if "whois" in dir(whois):
                        lookup_results = whois.whois(question)
                    elif "query" in dir(whois):
                        lookup)results = whois.query(question).__dict__
	        except Exception as e:
			logger("An error in the underlying python whois lookup module occured during the lookup of: " + str(question))
			logger("    the error was: " + str(e) )
			lookup_results = {}
                results = json_validator(lookup_results)
                update_cache(question,results)
                if threading.currentThread().getName() != 'backlog_worker':
                    rate_limit_timestamp=datetime.datetime.now()
                return results


def query_mem_cache(question):
	## This function is not used yet. code is inline elsewhere
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
		results = query_whois_internet(question)
		#results = 'Expired'
	return results

def query_elasticsearch_cache(question):
	results = elasticsearch_query(question)
	if results is None:
		return None
	results = results['hits']['hits'][0]['_source']
	# print(results)
	## Calculate the cached record timestamp, and the timestamp cache_max_age ago
	cache_expire_date = datetime.datetime.now() - datetime.timedelta(days=cache_max_age)
	## When read in from disk or ELK, cached_on is unicode, when passed from python-whois it is datetime 
	if isinstance(results['cached_on'],unicode):
		cache_entry_age = datetime.datetime.strptime(results['cached_on'], '%Y-%m-%d %H:%M:%S.%f')
	else:
		cache_entry_age = results['cached_on']
	## If the cache entry age has exceeded the configured limit, requery and update the cache
	if cache_entry_age < cache_expire_date:
		results = query_whois_internet(question)
		#results = 'Expired'
	return results
	

def whois_lookup(question):
	## Wrap the python-whois lookup with a cache
	timestamp = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
	stats['total_queries'] +=1
	if question in mem_cache.keys():
		logger ('cache - - [' + timestamp + ']  "' + question + '" "Mem_Cache:hit"')
		stats['mem_cache_hit']+=1
		results = query_mem_cache(question)
	## FIXME this is inefficient, we do 2 elasticsearch queries, should only do one. 
	elif use_elasticsearch_cache == True and query_elasticsearch_cache(question) is not None:
		logger ('cache - - [' + timestamp + ']  "' + question + '" "Elasticsearch_Cache:hit"')
		stats['elasticsearch_cache_hit']+=1
		results = query_elasticsearch_cache(question)
		if results is not None:
			update_cache(question,results)
			
	else:
		logger('cache - - [' + timestamp + ']  "' + question + '" "Mem_Cache:miss"')
		stats['mem_cache_miss']+=1
		results = query_whois_internet(question)
	return results


if len(sys.argv) != 2:
	print("Usage: caching-whois-proxy.py [-d|<DOMAIN>|<IP>]")
	print("All configuration of cache settings is via variables at the top of this script.")
	exit()

var = sys.argv[1]
load_timestamp = datetime.datetime.now()
rate_limit_timestamp = datetime.datetime.now()
stats = {"mem_cache_hit":0,"mem_cache_miss":0,"disk_cache_hit":0,"disk_cache_miss":0,"total_queries":0,"disk_cache_last_written":load_timestamp,"elasticsearch_cache_hit":0,"elasticsearch_cache_miss":0,"exceeded_rate_limit":0}
## Load the disk cache to mem_cache on program start
if use_disk_cache == True:
	mem_cache = load_disk_cache()

if var == '-d':
	print("logging to " + logfile)
	## Run the Whois network server
	net_thread = threading.Thread(name="whois_server",target=whois_server)
	net_thread.daemon = True
	net_thread.start()
	## Run the web server
	if rate_limit_use_backlog == True:
		backlog_questions = collections.deque([],rate_limit_backlog_size)
		backlog_thread = threading.Thread(name="backlog_worker", target=backlog_worker)
		backlog_thread.daemon = True
		backlog_thread.start()
	if enable_web_server == True:
		web_server()

else:
	## looks like query was run from command line
	## write to the disk cache immediately when run from command line
	disk_cache_write_interval=0
	rate_limit_queries=0
	answer = whois_lookup(var)
	try:
		print(json.dumps(answer,indent=4,sort_keys=False,default=str))
	except:
		print(answer)


