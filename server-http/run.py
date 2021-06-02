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