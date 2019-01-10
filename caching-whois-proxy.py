#!/usr/bin/python
import sys, datetime
## This is the python-whois package; pip install python-whois
import whois
from elasticsearch import Elasticsearch, helpers
import requests, json
import socket, threading
from urlparse import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer


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
			self.send_error(500,'Something went wrong. Query was: %s' % e)

	def do_POST(self):
		self.send_error(404,'Something went wrong. You can not POST to this site. ')
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

def handle_whois_client_connection(client_socket):
	request = client_socket.recv(1024)
	print 'Received {}'.format(request)
	question = request.rstrip()
	answer=whois_lookup(question)
	text = json.dumps(answer,indent=4, sort_keys=True, default=str)
	#answer='DEBUG'
	client_socket.send(text)
	client_socket.close()

def whois_server():
	bind_ip = '0.0.0.0'
	bind_port = 49
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((bind_ip, bind_port))
	server.listen(5)  # max # of open connections
	while True:
		client_sock, address = server.accept()
		print 'Accepted connection from {}:{}'.format(address[0], address[1])
		client_handler = threading.Thread(target=handle_whois_client_connection, args=(client_sock,) )
		client_handler.start()


def whois_lookup(question):
	stats['total_queries'] +=1
	if question in mem_cache.keys():
		print("DEBUG: Mem_Cache hit")
		stats['mem_cache_hit']+=1
		results = mem_cache[question]
	else:
		print("DEBUG: Mem_Cache miss")
		stats['mem_cache_miss']+=1
		results = whois.whois(question)
		#send_to_elasticsearch(results)
		mem_cache[question] = results
	disk_cache = open('whois.cache', 'w')  
	disk_cache.write(json.dumps(mem_cache, default=str))  
	disk_cache.close()
	return results



var = sys.argv[1]
mem_cache = load_disk_cache()
stats = {"mem_cache_hit":0,"mem_cache_miss":0,"disk_cache_hit":0,"disk_cache_miss":0,"total_queries":0}

if var == '-d':
	## Run the Whois server, DEBUG I need to thread this
	whois_server()
	## Run the web server, I'll figure out how to background later
	web_port=8080
	server = HTTPServer(('', web_port), webHandler)
	print 'Started httpserver on port ' , web_port
	server.serve_forever()
else:
	## looks like run from command line
	answer = whois_lookup(var)
	print(answer)