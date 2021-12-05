import netlas
import json
from pprint import pprint
import requests
import argparse
import eventlet
def count_cve_score(host,ip):

	buckets = host["aggregations"]["cves"]["buckets"]
	total_score = 0
	exploit_links = []
	try:
		for bucket in buckets:
			cve_string 		= bucket["key"].split(",")
			save_cve_string = cve_string
			severity 		= cve_string[0].replace("{severity=","")
			if severity   == "MEDIUM" :
				score = 1
			elif severity == "HIGH" :
				score = 3
			elif severity == "CRITICAL" :
				score = 7
			total_score 	= total_score + score

			if save_cve_string[2] == " has_exploit=true":
				exploit_links.append(save_cve_string[len(save_cve_string)-1])
				if   severity == "MEDIUM" :
						exploit_score = 2
				elif severity == "HIGH" :
						exploit_score = 5
				elif severity == "CRITICAL" :
						exploit_score = 10
				total_score = total_score + exploit_score
	except:
		cve_score = 0
	for exploit in range(len(exploit_links)):
		print(exploit_links[exploit])
	return total_score

def count_services(host,ip):
	bucket_ports      = host["aggregations"]["ports"]["buckets"]
	bucket_service    = host["aggregations"]["services"]["buckets"]
	port_list         = []
	service_list   	  = []
	protocol_points = 0
	
	for x in range(len(bucket_ports)):
		port_list.append(bucket_ports[x]["key"])
	for x in range(len(bucket_service)):
		service_list.append(bucket_service[x]["key"])

	bad_protocols = ["pop3","imap","smtp","http","ftp","telnet"]
	for x in range(len(bad_protocols)):
		if(bad_protocols[x]) in service_list:
			protocol_points = protocol_points + 1 
	return [protocol_points , service_list]

def count_headers(host,ip):
	try:
		response = requests.get("http://" +  ip , verify = False , timeout = 1)
	except:
		try:
			response = requests.get("https://" + ip , verify = False ,timeout = 1)
		except:
			response = []
	
	buckets = host["items"]
	try:
		headers = response.headers
	except:
		headers = []
	security_headers = ["Referrer-Policy", "X-XSS-Protection", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]
	proxy_headers = ["HTTP_VIA","HTTP_X_FORWARDED_FOR","HTTP_FORWARDED_FOR", 
	"HTTP_X_FORWARDED", "HTTP_FORWARDED", "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR_IP", "VIA", 
	"X_FORWARDED_FOR", "FORWARDED_FOR", "X_FORWARDED", "FORWARDED", "CLIENT_IP", "FORWARDED_FOR_IP", 
	"HTTP_PROXY_CONNECTION","PROXY-AGENT","HTTP_X_CLUSTER_CLIENT_IP","HTTP_PROXY_CONNECTION",
	"X-PROXY-ID","Proxy-Connection","X-PROXY-ID","MT-PROXY-ID","X-TINYPROXY","X-Forwarded-For"]
	headers_score = 0
	for x in range(len(security_headers)):
		if (security_headers[x]) not in headers:
			headers_score = headers_score + 1
	for x in range(len(proxy_headers)):
		if(proxy_headers[x]) in headers:
			headers_score = headers_score + 3
			break
	return headers_score

def count_storage(host,ip):

	buckets         = host["items"]
	storage_score = 0
	for x in range(len(buckets)):
		if "redis" in buckets[x]["data"]:
			try:
				if buckets[x]["data"]["redis"]["config_response"]!= 'Error':
					storage_score = storage_score + 5
					print("Redis without password!")
			except:
				break
		if "memcached" in buckets[x]["data"]:
			try:
				if buckets[x]["data"]["memcached"]["curr_connections"] != None:
					storage_score = storage_score + 5
			except:
				break
	return storage_score

def count_tor(hots,ip):
	response = requests.get("https://check.torproject.org/torbulkexitlist")
	tor_points = 0
	try:
		if ip in response.text :
			tor_points = 5
	except:
		tor_points = 0
	return tor_points 

remember_services = []

def get_ipqualityscore_object(ip):
	url = "https://www.ipqualityscore.com/api/json/ip/pA5PECZYW7A1pFMc8YdkvEqJ1wI5exad/" + ip
	response = requests.get(url)
	json 	 = response.json()
	return json

if __name__ == "__main__":

	apikey   		  = "YOUR_API_KEY_HERE"
	netlas_connection = netlas.Netlas(api_key=apikey)
	get_file   		  = open("ip.txt" , "r")
	ip_list    		  = get_file.read().splitlines()
	score_file_host	  = open("score_file_host.txt", "w")
	only_score        = open("score.txt","w")
	remember_services = []

	for x in range(len(ip_list)):
		host_ip  = ip_list[x]
		json_ipquality_object = get_ipqualityscore_object(host_ip)
		print(json_ipquality_object)

		try:
			host 			  = netlas_connection.host(host_ip, 'ip', '')
		except:
			host 			  = netlas_connection.host(host_ip, 'domain', '')
		services 		  = count_services(host,host_ip)
		service_score     = services[0]
		remember_services = services[1]
		cve_score      	  = count_cve_score(host,host_ip)

		if ("http" in remember_services) or ("https" in remember_services):
			headers_score     = count_headers(host,host_ip)
		else:
			headers_score     = 0

		storage_score     = count_storage(host,host_ip)
		tor_count 	      = count_tor(host,host_ip)
		print("Services score : ",service_score)
		print("Cve score : ",     cve_score) 
		print("Headers_score : " ,headers_score)
		print("Storage_score : " ,storage_score)
		print("Tor_score : " ,tor_count)
		total_score 	  = service_score + cve_score + headers_score + storage_score + tor_count 
		fputs_string      = "Score of host " +  str(host_ip) + ": " + str(total_score) + "\n" + "   Services score: " + str(service_score)+ "\n"+ "   cve_score: " + str(cve_score) +"\n" + "   headers_score: " + str(headers_score) + "\n" +"   storage_score: " + str(storage_score)+ "\n" + "   tor_score :" + str(tor_count) + "\n"
		score_file_host.write(fputs_string)         # все по хосту
		only_score.write(str(total_score) +"\n")    # онли его пойнты


