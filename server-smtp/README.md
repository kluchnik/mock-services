# smtp-сервер

smtp-сервер для проверки получения почты с выводом в консоль, работает по классическому варианту rfc, для python3.  

1. Создать сертификат:  
#: openssl genrsa -aes256 -passout pass:12345678 -out server.key 2048  
#: openssl req -new -key server.key -passin pass:12345678 -out server.csr  
-> в качестве имени я использовал имя машины: Common Name (e.g. server FQDN or YOUR name) []:pc  
#: openssl x509 -req -passin pass:12345678 -days 1024 -in server.csr -signkey server.key -out server.crt  
#: openssl rsa -in server.key -out server_no_pass.key -passin pass:12345678  
#: mv server_no_pass.key server.key  
#: cat server.crt server.key > server.pem  
 
2. Запустить smtp-сервер:  
#: ./smtp-server.py --host 0.0.0.0 --port 587 --cert_file server.pem  

Пример работы:  
```
        Python SMTP proxy version 0.3 (TLS and STARTTLS enabled)
        TLS Mode: explicit (plaintext until STARTTLS)
        TLS Context: <ssl.SSLContext object at 0x7fdcdbb323f0>
 
Incoming connection from ('192.168.6.1', 39120)
-> EHLO localhost
<- 250-pc-2
<- 250 STARTTLS
-> STARTTLS
<- 220 Ready to start TLS
Peer: ('192.168.6.1', 39120) - negotiated TLS: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
-> EHLO localhost
<- 250-pc-2
<- 250-8BITMIME
<- 250-PIPELINING
<- 250-SIZE 33554432
<- 250-STARTTLS
<- 250-AUTH LOGIN PLAIN XOAUTH2
<- 250-DSN
<- 250 ENHANCEDSTATUSCODES
-> AUTH PLAIN AHNlcnZlcgAxMjM0NTY3OA==
<- 235 Authentication successful
-> MAIL FROM:<test.rubicon@cnpo.ru>
-> RCPT TO:<ikh@cnpo.ru>
-> DATA
---------- MESSAGE FOLLOWS ----------
Date: Tue, 01 Dec 2020 16:51:04 +0300
From: rubicon@example.ru
To: admin@example.ru
Subject: Firewall alert
 
This message informs you that firewall event occured
------------ END MESSAGE ------------
<- 250 OK
-> QUIT
```