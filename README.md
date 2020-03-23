# caching-whois-proxy

This proxy will handle whois lookup requests over a web api, via the command line, and from whois clients over port 43. The script is multi-threaded and supports caching whois lookup results in memory, on disk, and in elasticsearch. The script can send full whois lookup records in json format to syslog as well as elasticsearch. 

This is a wrapper for the pyhton whois library.  

## Configuration:
All configuration is performed via variables at the top of the script. 

## To run the script:
python caching-whois-proxy -d

## Description of web API
/ Basic webform allowing querying whois records

/api?query=NAME lookup the whois record for NAME and return the results.
  
/api?cache=NAME Immediatley returns a code 200, and then performs a lookup of NAME un the background, caching the results. Use this instead of query when you don't care about the whois lookups results and only want to ensure the domain is in the cache.
  
/config Shows some current configuration settings

/stats Shows current statistics for number of requests and cache performance since script start

## Syslog
The script can send records to syslog in JSON format. The logs will be written to the local syslog stream. If you want to forward them elsewhere, modify the rsyslog/syslog-ng configuration to forward  to a remote syslog server. You will need to change the code in send_to_syslog to change the facility or priority. The script does not currently support logging it's own operational logs to sysylog; they are written to a file defined by the logfile variable
  
  
 ## Troubleshooting
 If you get an error stating "ImportError: No module named ordered_dict", you need to either downgrade urllib3 to 1.23 or upgrade requests.

