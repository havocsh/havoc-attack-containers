import time
import shutil
import subprocess
from pathlib import Path


class HttpServer:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None
        self.server_process = None

    def set_args(self, args, public_ip, hostname, local_ip):
        self.args = args
        self.host_info = [public_ip, hostname] + local_ip
        return True
    
    def create_listener(self):
        if 'listener_type' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify listener_type', 'forward_log': 'False'}
            return output
        listener_type = self.args['listener_type'].lower()
        if 'Port' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify Port', 'forward_log': 'False'}
            return output
        port = self.args['Port']
        if not isinstance(port, int):
            try:
                int(port)
            except:
                output = {'outcome': 'failed', 'message': 'Port must be a number', 'forward_log': 'False'}
                return output

        if listener_type == 'https':
            ssl_cert = Path('/opt/havoc/server.pem')
            if ssl_cert.is_file():
                self.server_process = subprocess.Popen(
                    [
                        '/usr/bin/python3',
                        '-m',
                        'uploadserver',
                        str(port),
                        '--server-certificate',
                        '/opt/havoc/server.pem',
                        '--directory',
                        '/opt/havoc/shared/'
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
            self.server_process = subprocess.Popen(
                ['/usr/bin/python3', '-m', 'uploadserver', str(port), '--directory', '/opt/havoc/shared/'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        else:
            output = {'outcome': 'failed', 'message': 'listener_type must be http or https', 'forward_log': 'False'}
            return output
        time.sleep(3)
        if self.server_process.poll():
            server_process_out = self.server_process.communicate()
            server_message = server_process_out[0].decode('utf-8')
            output = {'outcome': 'failed', 'message': server_message, 'forward_log': 'False'}
            return output
        else:
            output = {'outcome': 'success', 'create_listener': {'listener_type': listener_type, 'Port': port}, 'forward_log': 'True'}
            return output

    def kill_listener(self):
        if not self.server_process:
            output = {'outcome': 'failed', 'message': 'no listener is running', 'forward_log': 'False'}
            return output
        self.server_process.terminate()
        output = {'outcome': 'success', 'kill_listener': 'listener stopped', 'forward_log': 'True'}
        return output

    def cert_gen(self):
        if 'cert_type' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing cert_type', 'forward_log': 'False'}
            return output
        cert_type = self.args['cert_type']
        if cert_type == 'self-signed':
            required_params = ['cert_country', 'cert_state', 'cert_locale', 'cert_org', 'cert_org_unit', 'cert_host']
            for param in required_params:
                if param not in self.args:
                    output = {'outcome': 'failed', 'message': f'Missing {param}', 'forward_log': 'False'}
                    return output
            cert_country = self.args['cert_country']
            cert_state = self.args['cert_state']
            cert_locale = self.args['cert_locale']
            cert_org = self.args['cert_org']
            cert_org_unit = self.args['cert_org_unit']
            cert_host = self.args['cert_host']
            if cert_host == 'public_ip':
                host = self.host_info[0]
            if cert_host == 'local_ip':
                host = self.host_info[2]
            subj = f'/C={cert_country}/ST={cert_state}/L={cert_locale}/O={cert_org}/OU={cert_org_unit}/CN={host}'
            p = subprocess.Popen(
                ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', '/opt/havoc/server.pem',
                 '-out', '/opt/havoc/server.pem', '-days', '365', '-nodes', '-sha256', '-subj', subj],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            openssl_out = p.communicate()
            openssl_message = openssl_out[1].decode('utf-8')
            if 'problems making Certificate Request' not in openssl_message:
                output = {'outcome': 'success', 'cert_gen': {'host': host, 'subj': subj}, 'forward_log': 'True'}
            else:
                output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'True'}
            return output
        if cert_type == 'ca-signed':
            if 'domain' not in self.args:
                output = {'outcome': 'failed', 'message': 'Missing domain for certificate registration', 'forward_log': 'False'}
                return output
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
                with open(f'/etc/letsencrypt/live/{domain}/privkey.pem', 'r') as privkey_f:
                    privkey = privkey_f.read()
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            try:
                with open(f'/etc/letsencrypt/live/{domain}/fullchain.pem', 'r') as fullchain_f:
                    fullchain = fullchain_f.read()
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            
            with open('/opt/havoc/server.pem', 'w+') as server_f:
                server_f.write(privkey)
                server_f.write(fullchain)
            output = {'outcome': 'success', 'cert_gen': {'domain': domain, 'email': email}, 'forward_log': 'True'}
            return output
        output = {'outcome': 'failed', 'message': 'cert_type must be self-signed or ca-signed', 'forward_log': 'False'}
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
