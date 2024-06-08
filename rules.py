import ipaddress
import dns_server
import re
import logging
import pickle
"""

"""
logger = logging.getLogger("rules")
#logging.basicConfig(level=logging.WARNING)

class Rule:
	def __init__(self, domain_regex : str):
		self.domain_regex = domain_regex
	def is_match(self, domain_name, qtype):
		return re.search(self.domain_regex, domain_name) is not None
	def resolve():
		raise NotImplementedError
	def __eq__(self, other )->bool:
		return self.domain_regex == other.domain_regex

class IP_bind(Rule):
	def __init__(self, domain_name : str, ip_address : ipaddress.ip_address, rtype : str):
		super().__init__(domain_name)
		self.ip_address = ip_address
		self.rtype = rtype

	def resolve(self, domain_name : str, qtype : str):
		return str(self.ip_address)

	def is_match(self, domain_name, qtype):
		return self.domain_regex == domain_name and self.rtype == qtype
	def __str__(self):
		return self.domain_regex + "\tbind to\t\t" + str(self.ip_address) + "\t" + self.rtype

class DNS_rule(Rule):
	def __init__(self, domain_regex , dns_server : dns_server.DNS_server):
		super().__init__(domain_regex)
		self.dns_server = dns_server

	def resolve(self, domain_name : str, qtype):
		return self.dns_server.resolve(domain_name, qtype)
	def __str__(self):
		return self.domain_regex + "\tresolve via\t" + str(self.dns_server)

class Resolver:
	def __init__(self):
		self.rules = []
		self.default_dns = dns_server.DNS_server(None, None)

	def resolve_domain_name(self, domain_name, qtype):

		for rule in self.rules :
			if rule.is_match(domain_name, qtype):
				return(rule.resolve(domain_name, qtype))

		if (self.default_dns.ip_addresses is None):
			return None

		return self.default_dns.resolve(domain_name)

	def load_rules(self, path_to_rules, path_to_default_dns_server):
		with open(path_to_rules, 'rb') as f:
			self.rules = pickle.load(f)
		with open(path_to_default_dns_server, 'rb') as f:
			self.default_dns = pickle.load(f)

	def save_rules(self, path_to_rules, path_to_default_dns_server):
		with open(path_to_rules, 'wb') as f:
			pickle.dump(self.rules, f)

		with open(path_to_default_dns_server, 'wb') as f:
			pickle.dump(self.default_dns, f)

	def add_rule(self, rule):
		"""
		false means element already exists
		"""

		if (rule in self.rules):
			return False
		self.rules.append(rule)
		return True

	def overwrite_rule(self, rule : Rule)->bool:
		"""
		false means rule not found to be overwritten
		"""
		index = self.find_rule(rule)
		if(index != -1):
			self.rules[index] = rule
			return True
		return False

	def find_rule(self, rule : Rule):
		"""
		-1 means rule not found
		"""
		for i in range (0, len(self.rules)):
			if self.rules[i] == rule: return i
		return -1

	def remove_rule(self, domain_regex):
		index = self.find_rule(domain_regex)
		if (index == -1):
			return False
		self.rules.remove(index)
		return True

	def edit_rule():
		raise NotImplementedError

	def __contains__(self, rule):
		if issubclass(Rule, type(rule)) == False:
			raise Exception("element must be a subclass of Rule")

		for element in self.rules:
			if element.domain_regex == rule.domain_regex:
				return True
		return False
	def __str__(self):
		result = ""
		for i in range (0, len(self.rules)):
			result += (f"{i} {self.rules[i].__str__()}\n")
		result += f"default :\t{self.default_dns.name}\t\t({self.default_dns.ip_addresses})"
		return result
def handle_args():
	raise NotImplementedError


def test():
	resolver = Resolver()

	resolver.load_rules("rules", "default_server")

	resolver.print_rules()
if __name__ == "__main__":
	test()