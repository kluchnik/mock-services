#!/bin/python3

import argparse
import sys
import ssl
import smtpd
import asyncore, asynchat

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
				self.push('250-%s' % self.fqdn)
				self.push('250-8BITMIME')
				self.push('250-PIPELINING')
				self.push('250-SIZE 33554432')
				self.push('250-STARTTLS')
				self.push('250-AUTH LOGIN PLAIN XOAUTH2')
				self.push('250-DSN')
				self.push('250 ENHANCEDSTATUSCODES')
				print('<- 250-{}\n<- 250-8BITMIME\n<- 250-PIPELINING\n<- 250-SIZE 33554432\n<- 250-STARTTLS\n<- 250-AUTH LOGIN PLAIN XOAUTH2\n<- 250-DSN\n<- 250 ENHANCEDSTATUSCODES'.format(self.fqdn))
			else:
				self.push('250-%s' % self.fqdn)
				self.push('250 STARTTLS')
				print('<- 250-{}\n<- 250 STARTTLS'.format(self.fqdn))

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

