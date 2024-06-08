import ipaddress
import dns.resolver
import logging

logger = logging.getLogger("dns_server.py")

"""
this file contains the class DNS_server intended to resolve domain names
"""

class DNS_server:
	def __init__(self, name : str, ip_addresses : list[ipaddress.ip_address]):
		self.ip_addresses = ip_addresses
		self.name = name

	def resolve(self, domain_name : str, qtype)->str:
		try:
			return self.query(domain_name, qtype)[0].to_text()
		except Exception as e:
			logger.warning(e)
			return None

	def query(self, domain_name : str, qtype):
		try:
			return dns.resolver.resolve_at(self.ip_addresses[0], domain_name, qtype)
		except dns.resolver.NoAnswer as e:
			logger.warning(e)
			return None

	def __str__(self):
		return self.name +" " + str(self.ip_addresses)
	def __eq__(self, other):
		return self.name == other.name

def test():
	while True:
		s = DNS_server("name", ["178.22.122.100"])
		try :
			ans = s.query(input("domain name : "))
			print(ans[0].to_text())
		except Exception as e:
			print(e)
if __name__ == "__main__":
	test()