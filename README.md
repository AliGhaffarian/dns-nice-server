# dns-nice-server
how to use :
install dependancies : dnslib,dnspython
run server.py with --udp or --tcp or both
how to config:
  **rules**:
    there are two types of rules:
    1_ bind the domain name to an ip (rules.IP_bind) 
      needs a domain name an dns record(typically an ipv4 address) and types of the record ('A' for ipv4)
    2_ resolve a range of domain names via a dns server (rules.DNS_rule)
      needs a dns server (dns_server.DNS_server) and a domain name pattern (will execute for any matching domain name for the given pattern)
    
  first you need to make a resolver from rules.Resolver and assign it a dns server ( dns_server.DNS_server )
  then call add_rule for each rule you want to add
  put your configs in the server.config_resolver function
  rules are read from first to last and the first match is executed
  example:
  
  1_ .*spotify\\..\* resolve via 8.8.8.8
  2_ default resolve via 1.1.1.1
  
  in this case any domain name that includes spotify. will be resolved via 8.8.8.8 otherwise 1.1.1.1
  
  dns_server.DNS_server:
    takes a domain name regex and a list of ip addresses
