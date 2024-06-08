import ipaddress

def is_valid_ip(ip)-> bool | Exception:
	try :
		ipaddress.ip_address(ip)
		return True
	except Exception as e:
		return e
