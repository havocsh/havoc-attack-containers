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

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
        return True

    def start_server(self):
        if 'listen_port' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify listen_port', 'forward_log': 'False'}
            return output
        listen_port = self.args['listen_port']
        if not isinstance(listen_port, int):
            output = {'outcome': 'failed', 'message': 'listen_port must be type int', 'forward_log': 'False'}
            return output

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
                    [
                        '/usr/local/bin/twistd',
                        '-no',
                        'web',
                        f'--listen=ssl:{listen_port}'
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
        else:
            self.twisted_process = subprocess.Popen(
                ['/usr/local/bin/twistd', '-no', 'web', f'--listen=tcp:{listen_port}', '--path=/opt/havoc/shared/'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        time.sleep(3)
        if self.twisted_process.poll():
            twisted_process_out = self.twisted_process.communicate()
            twisted_message = twisted_process_out[0].decode('utf-8')
            output = {'outcome': 'failed', 'message': twisted_message, 'forward_log': 'False'}
            return output
        else:
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
            if 'writing new private key' in openssl_message and 'problems making Certificate Request' not in openssl_message:
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
            p = subprocess.Popen(
                ['/usr/bin/certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '-d', domain, '-m', email],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            certbot_out = p.communicate()
            certbot_message = certbot_out[1].decode('utf-8')
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
            #p = subprocess.Popen(
            #    [
            #        '/usr/bin/openssl', 'rsa', '-outform', 'der', '-in', '/opt/havoc/server-priv.pem',
            #        '-out', '/opt/havoc/server-priv.key'
            #    ],
            #    stdin=subprocess.PIPE,
            #    stdout=subprocess.PIPE,
            #    stderr=subprocess.PIPE
            #)
            #openssl_out, openssl_err = p.communicate()
            #openssl_message = openssl_err.decode('utf-8')
            #if 'writing RSA key\n' in openssl_message:
            #    output = {'outcome': 'success', 'message': openssl_message, 'forward_log': 'True'}
            #else:
            #    output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'False'}
            #return output

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
