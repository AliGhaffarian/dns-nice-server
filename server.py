#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import rules
import dns_list
import logging
import ip_bind_list
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("server")

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('example.com.')
IP = '0.0.0.0'
TTL = 60 * 5
PORT = 53
soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)


records = {
	D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record]
}

records["test"] = [A("1.2.3.4")]
resolver = rules.Resolver()
resolver.add_rule(rules.DNS_rule(".*", dns_list.electro))


def dns_response(request):
	global resolver


	#print(request)

	reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

	qname = request.q.qname
	qn = str(qname)
	qtype = request.q.qtype
	qt = QTYPE[qtype]

	#if qt != 'A' :
		#logger.info(f"{qt} is not supported currenty sending empty response")
		#return reply.pack(), None

	qn = qn[0:len(qn) - 1]
	#for name, rrs in records.items():
	#if name == qn:
	# for rdata in rrs:
	# 	rqt = rdata.__class__.__name__
	#if qt in ['*', rqt]:
	resolution = A("0.0.0.0")
	try:
		resolution = eval(compile(f"{qt}(resolver.resolve_domain_name(qn, qt))", "", "eval"))
	except:
		return reply.pack(), None

	reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, qt), rclass=1, ttl=TTL, rdata=resolution))#here
	logger.debug(f"{qn} -> {resolution}")

	reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

	#print("---- Reply:\n", reply)

	return reply.pack(),resolution


class BaseRequestHandler(socketserver.BaseRequestHandler):

	def get_data(self):
		raise NotImplementedError

	def send_data(self, data):
		raise NotImplementedError

	def handle(self):
		#now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
		#print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
		#                                      self.client_address[1]))
		try:
			data = self.get_data()
			request = DNSRecord.parse(data)
			#print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
			(resolution, ip) = dns_response(request)
			logger.info(f"request from {self.client_address} domain name :{str(request.q.qname)}, question type : {QTYPE[request.q.qtype]} -> {ip if ip is not None else str()}")
			self.send_data(resolution)
		except Exception:
			traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def config_resolver():
	global resolver
	#spotify
	resolver.add_rule(rules.DNS_rule(".*spotify\.com", dns_list.radar))
	resolver.add_rule(rules.DNS_rule(".*\.scdn\.co", dns_list.radar))
	resolver.add_rule(rules.DNS_rule(".*\.spotifycdn\.com", dns_list.radar))
	resolver.add_rule(rules.DNS_rule(".*\.akamaized\.net", dns_list.radar))

	#discord
	# resolver.add_rule(rules.DNS_rule(".*discord\..*", dns_list.electro))

	# #last pass
	# resolver.add_rule(rules.DNS_rule(".*\.lastpass\.com", dns_list.shecan))

	# #googleapis
	# resolver.add_rule(rules.DNS_rule(".*\.googleapis\.com", dns_list.radar))

	# #nvidia
	# resolver.add_rule(rules.DNS_rule(".*\.nvidia\.com", dns_list.radar))
	# resolver.add_rule(rules.DNS_rule(".*geforce\.com", dns_list.radar))
	# resolver.add_rule(rules.DNS_rule(".*\.nvidiagrid\.net", dns_list.radar))

	# #ea;apex
	# resolver.add_rule(rules.DNS_rule(".*\.ea\.com", dns_list.electro))
	# resolver.add_rule(rules.DNS_rule(".*\.tnt-ea\.com", dns_list.electro))
	# resolver.add_rule(rules.DNS_rule(".*\.eac-cdn\.com", dns_list.electro))
	# #microsoft
	# resolver.add_rule(rules.DNS_rule(".*\.dns.msftncsi\.com", resolver.default_dns))
	# resolver.add_rule(rules.DNS_rule(".*\.msftconnecttest\.com", resolver.default_dns))

	# resolver.add_rule(rules.DNS_rule(".*\.cloudflareclient\.com", dns_list.electro))

	# resolver.add_rule(rules.DNS_rule(".*\.cloudflare-dns\.com", resolver.default_dns))
	# #epic games
	# resolver.add_rule(rules.DNS_rule(".*\.epicgames\.com", dns_list.shecan))
	# resolver.add_rule(rules.DNS_rule(".*\.arkoselabs\.com", dns_list.shecan))
	# resolver.add_rule(rules.DNS_rule(".*\.launchdarkly\.com", dns_list.shecan))
	# resolver.add_rule(rules.DNS_rule(".*\.unrealengine\.com", dns_list.shecan))
	# resolver.add_rule(rules.DNS_rule(".*\.epicgames\.dev", dns_list.shecan))

	resolver.add_rule(rules.IP_bind("content.cfx.re", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("users.cfx.re", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("sentry.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("lambda.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("keymaster.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("cnl-hb-live.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("policy-live.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("changelogs-live.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("servers-frontend.fivem.net", ip_bind_list.shecan_server, 'A'))
	resolver.add_rule(rules.IP_bind("registry-internal.fivem.net", ip_bind_list.shecan_server, 'A'))

	resolver.add_rule(rules.IP_bind("status.cfx.re", ip_bind_list.electro_server, 'A'))
	resolver.add_rule(rules.IP_bind("metrics.fivem.net", ip_bind_list.electro_server, 'A'))
	resolver.add_rule(rules.IP_bind("status.fivem.net", ip_bind_list.electro_server, 'A'))
	resolver.add_rule(rules.IP_bind("synapse.fivem.net", ip_bind_list.electro_server, 'A'))
	resolver.add_rule(rules.IP_bind("runtime.fivem.net", ip_bind_list.electro_server, 'A'))
	resolver.default_dns = dns_list.radar
	resolver.rules.reverse()
	logger.debug(f"resolver rules after user configs {str(resolver)}")

def main():
	parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
	parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
	parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
	parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
	parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')

	config_resolver()

	args = parser.parse_args()
	if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

	print("Starting nameserver...")

	servers = []
	if args.udp: servers.append(socketserver.ThreadingUDPServer((IP, PORT), UDPRequestHandler))
	if args.tcp: servers.append(socketserver.ThreadingTCPServer((IP, PORT), TCPRequestHandler))

	for s in servers:
		thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
		thread.daemon = True  # exit the server thread when the main thread terminates
		thread.start()
		print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

	try:
		while 1:
			time.sleep(1)
			sys.stderr.flush()
			sys.stdout.flush()

	except KeyboardInterrupt:
		pass
	finally:
		for s in servers:
			s.shutdown()

if __name__ == '__main__':
    main()
