#!/usr/bin/python

__author__ = "ChrisPark(namegpark)"

import json, urllib, urllib2

class MetaScan():
	def __init__(self):
		self.addr = "http://[IP : PORT]/metascan_rest" #Your Metascan IP & Port
		self.apikey = "APIKEY" # Metascan APIKey

	def runHashScan(self, hash_value):
		result = dict()
		req = urllib2.Request(self.addr + "/hash/" + hash_value)
		req.add_header('apikey', self.apikey)
		resp = urllib2.urlopen(req)
		jdata = json.loads(resp.read())
		for i in jdata["scan_results"]["scan_details"]:
			if jdata["scan_results"]["scan_details"][i]["scan_result_i"] == 1:
				result[i] = jdata["scan_results"]["scan_details"][i]["threat_found"]
			else:
				result[i] = None
		return result

	def runUploadScan(self, file_name, file_path):
		result = dict()
		data_id = self.getDataId(file_name, file_path)
		req = urllib2.Request(self.addr + "/file/" + data_id)
		req.add_header('apikey', self.apikey)
		jdata = json.loads(urllib2.urlopen(req).read())
		while True:
			if jdata["scan_results"]["progress_percentage"] == 100:
				for i in jdata["scan_results"]["scan_details"]:
					if jdata["scan_results"]["scan_details"][i]["scan_result_i"] == 1:
						result[i] = jdata["scan_results"]["scan_details"][i]["threat_found"]
					else:
						result[i] = None
				break
			else:
				continue
		return result

	def getDataId(self, file_name, file_path):
		buf = open(file_path, 'rb').read()
		req = urllib2.Request(self.addr + "/file")
		req.add_header('apikey', self.apikey)
		req.add_header('filename', file_name)
		req.add_data(buf)
		data_id = json.loads(urllib2.urlopen(req).read())["data_id"]
		return data_id


if __name__ == '__main__':
	mt = MetaScan()