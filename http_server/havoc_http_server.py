import time
import shutil
import subprocess
from pathlib import Path


class HttpServer:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None
        self.twisted_process = None

    def set_args(self, args, public_ip, hostname, local_ip):
        self.args = args
        self.host_info = [public_ip, hostname] + local_ip
        return True

    def create_listener(self):
        if 'listener_type' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify listener_type', 'forward_log': 'False'}
            return output
        listener_type = self.args['listener_type']
        if 'Port' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify Port', 'forward_log': 'False'}
            return output
        port = self.args['Port']
        if not isinstance(port, int):
            try:
                port = int(port)
            except:
                output = {'outcome': 'failed', 'message': 'Port must be a number', 'forward_log': 'False'}
                return output

        if listener_type == 'https':
            ssl_cert = Path('/opt/havoc/server-priv.key')
            if ssl_cert.is_file():
                self.twisted_process = subprocess.Popen(
                    [
                        '/usr/local/bin/twistd',
                        '-no',
                        'web',
                        f'--listen=ssl:{port}'
                        ':privateKey=/opt/havoc/server-priv.key'
                        ':certKey=/opt/havoc/server-chain.pem',
                        '--path=/opt/havoc/shared/'
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            else:
                output = {'outcome': 'failed', 'message': 'missing certificate: run cert_gen first',
                          'forward_log': 'False'}
                return output
        elif listener_type == 'http':
            self.twisted_process = subprocess.Popen(
                ['/usr/local/bin/twistd', '-no', 'web', f'--listen=tcp:{port}', '--path=/opt/havoc/shared/'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        else:
            output = {'outcome': 'failed', 'message': 'listener_type must be http or https', 'forward_log': 'False'}
            return output
        time.sleep(3)
        if self.twisted_process.poll():
            twisted_process_out = self.twisted_process.communicate()
            twisted_message = twisted_process_out[0].decode('utf-8')
            output = {'outcome': 'failed', 'message': twisted_message, 'forward_log': 'False'}
            return output
        else:
            output = {'outcome': 'success', 'listener': {'listener_type': listener_type, 'Port': port}, 'forward_log': 'True'}
            return output

    def kill_listener(self):
        if not self.twisted_process:
            output = {'outcome': 'failed', 'message': 'no listener is running', 'forward_log': 'False'}
            return output
        self.twisted_process.terminate()
        output = {'outcome': 'success', 'message': 'listener stopped', 'forward_log': 'True'}
        return output

    def cert_gen(self):
        if 'subj' not in self.args and 'domain' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing subj or domain', 'forward_log': 'False'}
            return output
        if 'subj' in self.args and 'domain' in self.args:
            output = {'outcome': 'failed', 'message': 'Specify subj or domain but not both', 'forward_log': 'False'}
            return output
        if 'subj' in self.args:
            subj = self.args['subj']
            p = subprocess.Popen(
                ['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', '/opt/havoc/server-priv.key',
                 '-out', '/opt/havoc/server-chain.pem', '-days', '365', '-nodes', '-subj', f'{subj}'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            openssl_out = p.communicate()
            openssl_message = openssl_out[1].decode('utf-8')
            if 'problems making Certificate Request' not in openssl_message:
                output = {'outcome': 'success', 'message': openssl_message, 'forward_log': 'True'}
            else:
                output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'True'}
            return output
        if 'domain' in self.args:
            if 'email' not in self.args:
                output = {'outcome': 'failed', 'message': 'Missing email for certificate registration', 'forward_log': 'False'}
                return output
            domain = self.args['domain']
            email = self.args['email']
            if 'test_cert' in self.args and self.args['test_cert'].lower() == 'true':
                certbot_command = ['/usr/bin/certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '--test-cert', '-d', domain, '-m', email]
            else:
                certbot_command = ['/usr/bin/certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '-d', domain, '-m', email]
            p = subprocess.Popen(
                certbot_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            certbot_out = p.communicate()
            certbot_message = certbot_out[0].decode('utf-8')
            if 'Successfully received certificate' not in certbot_message:
                output = {'outcome': 'failed', 'message': certbot_message, 'forward_log': 'False'}
                return output
            try:
                shutil.copyfile(f'/etc/letsencrypt/live/{domain}/fullchain.pem', '/opt/havoc/server-chain.pem')
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            try:
                shutil.copyfile(f'/etc/letsencrypt/live/{domain}/privkey.pem', '/opt/havoc/server-priv.key')
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            output = {'outcome': 'success', 'message': 'Certificate files written to /opt/havoc/', 'forward_log': 'True'}
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
