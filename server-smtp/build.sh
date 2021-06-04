#!/bin/bash

echo 'Проверяем версию python'
/bin/python3 -V

echo 'Проверяем наличие smtpd'
echo "import smtpd;print(smtpd.__version__)" | python3

echo 'Создаем скрипт для запуска smtp-сервера)'
cat > /tmp/smtp-server.py <<EOF
#!/bin/python3

import argparse
import sys
import ssl
import smtpd
import asyncore, asynchat

def print(text):
	with open("/tmp/smtp.log", "a") as f:
		f.write("{}\n".format(text))

def create_parser():
	parser = argparse.ArgumentParser(description='mock SMTP-server')
	parser.add_argument('--host', default='0.0.0.0', type=str, help='ip-address smtp-server (ex. --host 0.0.0.0)')
	parser.add_argument('--port', default=587, type=int, help='port smtp-server (ex. --port 587)')
	parser.add_argument('--cert_file', default='server.pem', type=str, help='certificate file server.crt + server.key = server.pem (ex. --cert_file server.pem)')
	return parser

def get_certificate(cert_file):
	sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	sslctx.load_cert_chain(certfile=cert_file, keyfile=cert_file)
	return sslctx

class Options():
	localhost = '0.0.0.0'
	localport = 587
	sslctx = None
	starttls = True

class SMTPChannel(smtpd.SMTPChannel):
	def smtp_EHLO(self, arg):
		if not arg:
			self.push('501 Syntax: HELO hostname')
			print('<- 501 Syntax: HELO hostname')
		elif self.seen_greeting:
			self.push('503 Duplicate HELO/EHLO')
			print('<- 503 Duplicate HELO/EHLO')
		else:
			self.seen_greeting = arg
			if isinstance(self.conn, ssl.SSLSocket):
				self.push('250-{}'.format(self.fqdn))
				self.push('250-8BITMIME')
				self.push('250-PIPELINING')
				self.push('250-SIZE 33554432')
				self.push('250-STARTTLS')
				self.push('250-AUTH LOGIN PLAIN XOAUTH2')
				self.push('250-DSN')
				self.push('250 ENHANCEDSTATUSCODES')
				print('<- 250-{}'.format(self.fqdn))
				print('<- 250-8BITMIME')
				print('<- 250-PIPELINING')
				print('<- 250-SIZE 33554432')
				print('<- 250-STARTTLS')
				print('<- 250-AUTH LOGIN PLAIN XOAUTH2')
				print('<- 250-DSN')
				print('<- 250 ENHANCEDSTATUSCODES')
			else:
				self.push('250-%s' % self.fqdn)
				self.push('250 STARTTLS')
				print('<- 250-{}'.format(self.fqdn))
				print('<- 250 STARTTLS')

	def smtp_STARTTLS(self, arg):
		if arg:
			self.push('501 Syntax error (no parameters allowed)')
			print('<- 501 Syntax error (no parameters allowed)')
		elif self.smtp_server.starttls and not isinstance(self.conn, ssl.SSLSocket):
			self.push('220 Ready to start TLS')
			print('<- 220 Ready to start TLS')
			self.conn.settimeout(30)
			self.conn = self.smtp_server.ssl_ctx.wrap_socket(self.conn, server_side=True)
			self.conn.settimeout(None)
			# re-init channel
			asynchat.async_chat.__init__(self, self.conn)
			self.received_lines = []
			self.smtp_state = self.COMMAND
			self.seen_greeting = 0
			self.mailfrom = None
			self.rcpttos = []
			self.received_data = ''
			print('Peer: {} - negotiated TLS: {}'.format(self.addr, self.conn.cipher()))
		else:
			self.push('454 TLS not available due to temporary reason')
			print('<- 454 TLS not available due to temporary reason')

	def smtp_AUTH(self, arg):
		if 'PLAIN' in arg:
			self.authenticated = True
			self.push('235 Authentication successful')
			print('<- 235 Authentication successful')
		else:
			self.push('454 Temporary authentication failure')
			print('<- 454 Temporary authentication failure')

	def smtp_DATA(self, arg):
		if not self.seen_greeting:
			self.push('503 Error: send HELO first')
			print('<- 503 Error: send HELO first')
			return
		if not self.rcpttos:
			self.push('503 Error: need RCPT command')
			print('<- 503 Error: need RCPT command')
			return
		if arg:
			self.push('501 Syntax: DATA')
			print('<- 501 Syntax: DATA')
			return
		self.smtp_state = self.DATA
		self.set_terminator(b'\r\n.\r\n')
		self.push('354 Enter mail, end with "." on a line by itself')
		print('<- 354 Enter mail, end with "." on a line by itself')

	def smtp_QUIT(self, arg):
		self.push('221 Bye')
		print('<- 221 Bye')
		self.close_when_done()

	def found_terminator(self):
		line = self._emptystring.join(self.received_lines)
		if not 'Date:' in line.decode('ascii'):
			print('-> {}'.format(line.decode('ascii')))
		self.received_lines = []
		if self.smtp_state == self.COMMAND:
			sz, self.num_bytes = self.num_bytes, 0
			if not line:
				self.push('500 Error: bad syntax')
				print('<- 500 Error: bad syntax')
				return
			if not self._decode_data:
				line = str(line, 'utf-8')
			i = line.find(' ')
			if i < 0:
				command = line.upper()
				arg = None
			else:
				command = line[:i].upper()
				arg = line[i+1:].strip()
			max_sz = (self.command_size_limits[command] if self.extended_smtp else self.command_size_limit)
			if sz > max_sz:
				self.push('500 Error: line too long')
				print('<- 500 Error: line too long')
				return
			method = getattr(self, 'smtp_' + command, None)
			if not method:
				self.push('500 Error: command "{}" not recognized'.format(command))
				print('<- 500 Error: command "{}" not recognized'.format(command))
				return
			method(arg)
			return
		else:
			if self.smtp_state != self.DATA:
				self.push('451 Internal confusion')
				print('<- 451 Internal confusion')
				self.num_bytes = 0
				return
			if self.data_size_limit and self.num_bytes > self.data_size_limit:
				self.push('552 Error: Too much mail data')
				print('<- 552 Error: Too much mail data')
				self.num_bytes = 0
				return
			data = []
			for text in line.split(self._linesep):
				if text and text[0] == self._dotsep:
					data.append(text[1:])
				else:
					data.append(text)
			self.received_data = self._newline.join(data)
			args = (self.peer, self.mailfrom, self.rcpttos, self.received_data)
			kwargs = {}
			if not self._decode_data:
				kwargs = {
					'mail_options': self.mail_options,
					'rcpt_options': self.rcpt_options,
				}
			status = self.smtp_server.process_message(*args, **kwargs)
			self._set_post_data_state()
			if not status:
				self.push('250 OK')
				print('<- 250 OK')
			else:
				self.push(status)
				print('<- ', status)

class SMTPServer(smtpd.SMTPServer):
	def __init__(self, localaddr, remoteaddr, ssl_ctx=None, starttls=True):
		self.ssl_ctx = ssl_ctx
		self.starttls = starttls
		smtpd.SMTPServer.__init__(self, localaddr, remoteaddr)
		mode = 'explicit (plaintext until STARTTLS)' if starttls else 'implicit (encrypted from the beginning)'
		print('\tTLS Mode: {}\n\tTLS Context: {}'.format(mode, ssl_ctx))

	def handle_accept(self):
		pair = self.accept()
		if pair is not None:
			conn, addr = pair
			print('Incoming connection from {}'.format(addr))
			if self.ssl_ctx and not self.starttls:
				conn = self.ssl_ctx.wrap_socket(conn, server_side=True)
				print('Peer: {} - negotiated TLS: {}'.format(addr, conn.cipher()))
			channel = SMTPChannel(self, conn, addr)

class DebuggingServer(SMTPServer):
	# Do something with the gathered message
	def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
		lines = data.decode('ascii').split('\n')
		print('---------- MESSAGE FOLLOWS ----------')
		for line in lines:
			print(line)
		print('------------ END MESSAGE ------------')

def main():
	parser = create_parser()
	try:
		arg_space = parser.parse_args(sys.argv[1:])
		options = Options()
		options.localhost = arg_space.host
		options.localport = int(arg_space.port)
		options.sslctx = get_certificate(arg_space.cert_file)
	except Exception as e:
		print('error: parsing parameters - ', e)
		print('show ./smtp-server.py --help')
		sys.exit(1)
	print('\t{} (TLS and STARTTLS enabled)'.format(smtpd.__version__))
	smpt_server = DebuggingServer((options.localhost, options.localport), None, ssl_ctx=options.sslctx, starttls=options.starttls)
	try:
		asyncore.loop()
	except KeyboardInterrupt:
		pass
	except Exception as e:
		print('error: start asyncore - ', e)

if __name__ == '__main__':
	main()
EOF

echo 'Делаем файл испольняемым)'
chmod +x /tmp/smtp-server.py
ls -lh /tmp/smtp-server.py

echo 'Создаем RSA сертификат)'

echo "-----BEGIN CERTIFICATE-----
MIIDLzCCAhcCFFleKmX8plKx1EL5i7jmebZtgHt4MA0GCSqGSIb3DQEBCwUAMFQx
CzAJBgNVBAYTAlJVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBHBjLTIwHhcNMjAxMTMwMTUz
MzUxWhcNMjMwOTIwMTUzMzUxWjBUMQswCQYDVQQGEwJSVTETMBEGA1UECAwKU29t
ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYD
VQQDDARwYy0yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+alOLC+/
OqhCOOGHhex8d9BQl0HklSf+y0oVgVm/r1OVU79Vg1txdbM7L8xdj6CWR4yBqxqH
7rt/hqZV6PXO4JWlDhCn4St4opCBHRlHZf62qePYyGI4KJ+Y/JOp2I07lBP+15MN
Y+Qa9d9Uv9ThpS2eCwyNQdRUXcKAjzQyqqZ4T2XSAx+vghTRzkLWYbex+8lXrTkR
hS8OMHRUq/UoUsmKIRTavQYD1I3xzJ3kbdiWKROVyMQLjQGLjvUDaqlYyYVy5gHp
6cp3+neNvRWOOyxUl+0g1M9t1ukcY+0eMvwDZXUYvuf8BB/4GDp4UJaR9sxELwFX
iEU76KGVV+6UXwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDpTaS+ed9Ew1E10fJr
E3WeYfhiT0ffeyb3nuKDaW1v1b7G3TQRVR25vhjvNLRPPtWSX/cJgtx+HPh0WtBE
tP8XfUkHBBfOw1lyix+d8V1Kb0MELncai/P5MQAlNsR/39EX9KSNPt3iNp+FAEGD
z7Da9LbYcRv54w6lGbeS5/ay0mUkn3UcRXU7qXhC3DijuxHaom8+j6skPP70whkB
Gc6kGJ4pwRCwcAfq40iyoiSjwfKBX2e0Ye12plS/GfnYq6GmjOS44LQe4Pd1MUOE
dAUhciesNYutvX7bwWKEFH8UKf4f3+/yiyleWwMY9Vv3ekdD1StpHNrDuwOPxaqd
BhyG
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA+alOLC+/OqhCOOGHhex8d9BQl0HklSf+y0oVgVm/r1OVU79V
g1txdbM7L8xdj6CWR4yBqxqH7rt/hqZV6PXO4JWlDhCn4St4opCBHRlHZf62qePY
yGI4KJ+Y/JOp2I07lBP+15MNY+Qa9d9Uv9ThpS2eCwyNQdRUXcKAjzQyqqZ4T2XS
Ax+vghTRzkLWYbex+8lXrTkRhS8OMHRUq/UoUsmKIRTavQYD1I3xzJ3kbdiWKROV
yMQLjQGLjvUDaqlYyYVy5gHp6cp3+neNvRWOOyxUl+0g1M9t1ukcY+0eMvwDZXUY
vuf8BB/4GDp4UJaR9sxELwFXiEU76KGVV+6UXwIDAQABAoIBAQCJOYvkMaJUZWNw
zFWnQOLxICkL2oX/jeo4ZtIHNQNtJO3xCDvCZaKpZQhlL1lFtqijTxF+sKiCicCA
jDCwSVuaieYdIv6Df1dhUzgEfH6IC0bvfnMLQSFJAuAeBDPY+VgD/jGW4Bb+DsTa
3BRDFImqNralsBJ8Wm680knDbJdkv+F5woIc9ysMb/kLgypGlrd9wVihWjXCmStn
nkHiqnPhmFsEXZcMBFpwJJJC0RLNqXM0asXxr1tMhGr7Xq6wS+ezVx6Yu6qK9ccL
uay1Va1y7EZd+EXVZ5+XPr3giwvxFkF1v4V7Oqh2bcL/WFPgf/C+1z6hqd572PS5
5wIoSVWhAoGBAP4HPo+uk85kCL4qyB6yoMP0QtCzQpzRvGmsyDY0aeCgZ9FsMvHs
fHlqqj0msTWZKpTMnXWfWRGR4OKpJgKndj33+U0luTHEJMV2HTGIiBUK8O0c82lF
gaa4WYlgkHSR+mXwQiuLYCYCEIVWwtYDcrkj0P+GJPbKbxgVZBl6LxwHAoGBAPuZ
YkKpMXBDwzxrvyD3IYSwhLvNnEqfhy5hSs1t1XTlQBLfQ04EjIIRFyCas1kld7e4
x0vsCNp8EyVwLgUiIKt5nd9IDMWTC+vJcJntcIdwuIfxPeL0vEfuNDrok7yTGqQn
ANfyXE1WUQw9ZmJgjpiSyxLn4U8XIUEgmzjBQN7pAoGBALSwQnfBHbF4xh8+Hwp2
1JONctkwKPmS1gn0tJSZw5Xbgv0bkUEzjXZvwJeupe4R/I/K21WG+rvcn7GZz0ek
Bh8d+148rvYPJniuAyXwj5soJScDqMAAiLAmAMoOvbGtBAbuVqLSiJmAbm/pvryr
xzaZm1el+zTv2QWwcXsNxeSRAoGASdImV4LHI7ZuKWM/0A9SwVj9iRD6A5ctFbms
Nfw8/jBpjV/+onyJMXyMOZ/KcaShrMFFkIwvyNNQ1tJEXnM1/LoRTTsZrDrJ66PO
KwvU0ZiMPC7XRqkiOUS2BHbLKjBLR9C92Z6d4H8sBphZWxITpMalWOW6YPdbZX2I
ra1eOEkCgYEAijFONkQXQa8Zs197RARbJFXKbjH4zzhiHSdHjtSV5TkljfMT5ydM
L5Twn+dKhMQT2c8+FiQsiI0MtEtJf8fVqRkM5Nv0MKaQXk/Xgprf9SOiCAUZTCBA
9FF3FT3bO1ifAce6EqgNfKD+uuGJYl7vp+GKkvFqnjR8QZWptzS1Bzk=
-----END RSA PRIVATE KEY-----" > /tmp/server.pem

ls -lh /tmp/server.pem

echo 'Запуск smtp-сервера как демон'
echo > /tmp/smtp.log
/tmp/smtp-server.py --host 0.0.0.0 --port 587 --cert_file /tmp/server.pem > /dev/null &
sleep 1
ps aux | grep "/tmp/smtp-server.py" | grep -v grep