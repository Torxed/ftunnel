import sys, ssl, signal, time, base64
from socket import *
from select import epoll, EPOLLIN, EPOLLHUP

args = {}
positionals = []
for arg in sys.argv[1:]:
	if '--' == arg[:2]:
		if '=' in arg:
			key, val = [x.strip() for x in arg[2:].split('=')]
		else:
			key, val = arg[2:], True
		args[key] = val
	else:
		positionals.append(arg)

if not 'pem' in args:
	import glob
	try:
		args['pem'] = glob.glob('*.pem')[0]
	except:
		raise KeyError('Need to supply or create a .pem (cert+key) in this catalogue:  {}'.format(
			'openssl req -new -x509 -days 365 -nodes -out ftunnel.pem -keyout ftunnel.pem'
		))


def sig_handler(signal, frame):
	s.close()
	exit(0)
signal.signal(signal.SIGINT, sig_handler)

class http():
	def __init__(self, data=b''):
		self.data = data

	def parse(self):
		headers, payload = self.data.split(b'\r\n\r\n', 1)
		return base64.b64decode(payload)

	def build(self):
		headers = 'POST /{} HTTP/1.1\r\n'.format(time.time())
		headers += 'Host: hvornum.se\r\n'
		headers += 'Content-Length: {}\r\n'.format(len(self.data))
		headers += '\r\n'

		return bytes(headers, 'UTF-8') + base64.b64encode(self.data)

poller = epoll()
sockets = {}

local, port = args['source'].split(':')

s = socket()
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.bind((local, int(port)))
s.listen(4)
poller.register(s.fileno(), EPOLLIN|EPOLLHUP)
print(f'Bound INPUT to {local}:{port}')

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args['pem'], args['pem'])

sockets = {}
while 1:
	for fileno, event in poller.poll(0.25):
		if fileno == s.fileno():
			## Accept the client
			ns, na = s.accept()
			print(f'{na[0]} has connected.')
			
			## Redirect to destination
			destination = socket()
			target, port = args['destination'].split(':')
			destination.connect((target, int(port)))

			## If HTTP is pointed towards destination,
			## it means we're sending to another stunnel who can
			## extract the payload.. and it will act as a webserver
			## - which means we need to wrap the socket as if it's HTTPS traffic.
			if args['http'] == 'destination':
				print('  Wrapping DESTINATION socket')
				destination = ssl.wrap_socket(destination, server_side=False)
			## But if the source is HTTP, we need to act as a web server for the source instead.
			else:
				print('  Wrapping INPUT socket')
				ns = context.wrap_socket(ns, server_side=True)
			print(f'  Relay to {target} has been established.')

			## Create the mapping table for source <--> destination
			sockets[ns.fileno()] = {'sock' : ns, 'addr' : na, 'endpoint' : destination.fileno(), 'type' : 'source'}
			sockets[destination.fileno()] = {'sock' : destination, 'addr' : (target, int(port)), 'endpoint' : ns.fileno(), 'type' : 'destination'}

			poller.register(ns.fileno(), EPOLLIN|EPOLLHUP)
			poller.register(destination.fileno(), EPOLLIN|EPOLLHUP)

		elif fileno in sockets:
			print(f'Recieved data from {sockets[fileno]["addr"][0]} [{sockets[fileno]["type"]}]')
			data = sockets[fileno]['sock'].recv(8192)
			if len(data) <= 0:
				print(f'{sockets[fileno]["addr"][0]} closed the socket. Closing the endpoint {sockets[sockets[fileno]["endpoint"]]["addr"][0]}')
				try:
					sockets[fileno]['sock'].send(b'')
				except:
					sockets[fileno]['sock'].close()
					sockets[sockets[fileno]['endpoint']]['sock'].close()
					poller.unregister(fileno)
					poller.unregister(sockets[fileno]['endpoint'])
					del(sockets[sockets[fileno]['endpoint']])
					del(sockets[fileno])
					continue

			if sockets[fileno]['type'] == args['http']:
				print(f'  Unpacking payload before sending to endpoint')
				data = http(data).parse()
				sockets[sockets[fileno]['endpoint']]['sock'].send(data)
			else:
				print(f'  Encapsulating payload and sending to endpoint')
				data = http(data).build()
				sockets[sockets[fileno]['endpoint']]['sock'].send(data