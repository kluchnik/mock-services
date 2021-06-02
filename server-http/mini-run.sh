#!/bin/bash
# Мини ftp-сервер на flask

echo 'Проверяем наличие http-сервера'
echo flask --version

echo 'Производим конфигурирование http-сервера'
mkdir /home/web_server
echo > /home/web_server/run.py

cat > /home/web_server/run.py << EOF
#!/bin/python3
from flask import Flask
app = Flask(__name__)

@app.route('/')
def web_server():
    web_page = '''
<html>
    <body>
        <p id="p1">Example</p>
        <p id="p2"></p>
        <script type="text/javascript">
            document.getElementById("p2").innerHTML = "New text!";
        </script>
    </body>
</html>'''
    return web_page

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=80)
EOF

chmod +x /home/web_server/run.py

echo > /lib/systemd/system/web.service
echo > /var/log/web.log

cat > /lib/systemd/system/web.service << EOF
[Unit]
Description = test web server
[Service]
Type=simple
PIDFile=/run/web_server.pid
ExecStart = /home/web_server/run.py
StandardOutput=file:/var/log/web.log
StandardOutput=file:/var/log/web.log
[Install]
WantedBy = multi-user.target
EOF

echo 'Запускаем http-сервер'
systemctl stop web.service
systemctl start web.service
systemctl status web.service

echo 'Проверяем доступ к http-серверу'
sleep 1
wget http://192.168.6.100 -O /tmp/web.html 2>&1
echo '------------web-page------------'
cat /tmp/web.html
echo '--------------------------------'
