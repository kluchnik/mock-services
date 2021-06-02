#!/bin/python2
import time
import threading

from icapserver import *

class ExampleICAPHandler(BaseICAPRequestHandler):
    def example_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header('Methods', 'RESPMOD, REQMOD')
        self.set_icap_header('Service', 'ICAP Server' + ' ' + self._server_version)
        self.set_icap_header('Options-TTL', '3600')
        self.set_icap_header('Preview', '0')
        self.send_headers(False)
        
    def checking_user_agent(self, user_agent):
        acl_user_agent = ['Wget', 'Firefox']
        for item in acl_user_agent:
            if item in user_agent:
                return True
        return False
        
    def example_REQMOD(self):
        self.no_adaptation_required()

    def example_RESPMOD(self):
        self.set_icap_response(200)
        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)
            if not self.has_body:
                self.send_headers(False)
                return
        
        request = ' '.join(self.enc_req)
        print 'request: {}'.format(request)
        user_agent = self.enc_req_headers['user-agent'][0]
        print 'user-agent: {}'.format(user_agent)
        content_type = self.enc_res_headers['content-type']
        print 'content-type: {}'.format(content_type)
        
        if self.checking_user_agent(user_agent):
            self.set_enc_status(' '.join(self.enc_res_status))
            self.send_headers(True)
            content = ''
            while True:
                chunk = self.read_chunk()
                self.send_chunk(chunk)
                content += chunk
                if chunk == '':
                    break
            print 'content:\n{}'.format(content)
        else:
            self.set_enc_status('HTTP/1.1 451 Unavailable For Legal Reasons')
            self.send_headers(False)
            print 'content:\n\tHTTP/1.1 451 Unavailable For Legal Reasons'

class ExampleICAPServer():
    def __init__(self, addr='', port=1344):
        self.addr = addr
        self.port = port

    def start(self):
        self.server = ICAPServer((self.addr, self.port), ExampleICAPHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        return True

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        return True

def main():
    try:
        server = ExampleICAPServer()
        server.start()
        print 'Start icap-server'
        print 'Use Control-C to exit'
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print 'Stop icap-server'
        print "Finished"

if __name__ == '__main__':
    main()