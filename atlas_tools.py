import requests

def checkRelay(ip_addr,UTCtimestamp):
	r = requests.get("https://exonerator.torproject.org/?targetaddr=&targetPort=&ip="+ip_addr+"&timestamp="+ UTCtimestamp + "#relay")
	return (r.content.find("NEGATIVE") == -1)
