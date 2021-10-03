import subprocess
from pathlib import Path

class HttpServer:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None
        self.twisted_process = None

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
        return True

    def start_server(self):

        if 'listen_port' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify listen_port', 'forward_log': 'False'}
            return output
        listen_port = self.args['listen_port']

        if 'ssl' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify ssl', 'forward_log': 'False'}
            return output
        ssl = self.args['ssl']
        if isinstance(ssl, bool):
            if ssl:
                ssl = 'true'
            else:
                ssl = 'false'

        if ssl.lower() == 'true':
            ssl_cert = Path('/opt/havoc/server-priv.key')
            if ssl_cert.is_file():
                self.twisted_process = subprocess.Popen(
                    ['/usr/local/bin/twistd', '-no', 'web', f'--https={listen_port}', '-c',
                     '/opt/havoc/server-priv.key', '-k', '/opt/havoc/server-chain.pem', '--path', '/opt/havoc/shared/']
                )
            else:
                output = {'outcome': 'failed', 'message': 'missing certificate: run cert_gen first',
                          'forward_log': 'False'}
                return output
        else:
            self.twisted_process = subprocess.Popen(
                ['/usr/local/bin/twistd', '-no', 'web', f'--port={listen_port}', '--path', '/opt/havoc/shared/']
            )
        output = {'outcome': 'success', 'message': 'HTTP server started', 'forward_log': 'True'}
        return output

    def stop_server(self):
        if not self.twisted_process:
            output = {'outcome': 'failed', 'message': 'no server is running', 'forward_log': 'False'}
            return output
        self.twisted_process.terminate()
        output = {'outcome': 'success', 'message': 'HTTP server stopped', 'forward_log': 'True'}
        return output

    def cert_gen(self):
        if 'subj' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify subj', 'forward_log': 'False'}
            return output
        subj = self.args['subj']

        p = subprocess.Popen(
            ['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', '/opt/havoc/server-priv.key',
             '-out', '/opt/havoc/server-chain.pem', '-days', '365', '-nodes', '-subj', f'{subj}'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        openssl_out, openssl_err = p.communicate()
        message = openssl_err.decode('utf-8')
        if 'writing new private key' in message and 'problems making Certificate Request' not in message:
            output = {'outcome': 'success', 'message': message, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': message, 'forward_log': 'True'}
        return output

    def echo(self):
        match = {
            'foo': 'bar',
            'bar': 'baz',
            'ping': 'pong',
            'and then': 'no more and then',
            'pen testing is dead': 'long live pen testing',
            'never gonna give you up': 'never gonna let you down, never gonna run around and desert you',
            'never gonna make you cry': 'never gonna say goodbye, never gonna tell a lie and hurt you'
        }

        if 'echo' in self.args:
            echo = self.args['echo']
            if echo in match:
                output = {'outcome': 'success', 'echo': match[echo], 'forward_log': 'False'}
            else:
                output = {'outcome': 'success', 'echo': 'OK', 'forward_log': 'False'}
        else:
            output = {'outcome': 'success', 'echo': 'OK', 'forward_log': 'False'}

        return output
