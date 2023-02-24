import os
import time
import shutil
import signal
import subprocess


class CallExfilkit:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.http_process = None
        self.https_process = None

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
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
        if listener_type == 'http':
            self.http_process = subprocess.Popen(
                f'/HTTPUploadExfil/httpuploadexfil :{port} /opt/havoc/shared',
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                cwd=r'/HTTPUploadExfil'
            )
            time.sleep(5)
            if self.http_process.poll():
                output = {'outcome': 'failed', 'message': 'listener did not start, requested port may be in use', 'forward_log': 'False'}
                return output
            else:
                output = {'outcome': 'success', 'message': 'listener is running', 'forward_log': 'True'}
                return output
        else:
            output = {'outcome': 'failed', 'message': 'listener_type must be http', 'forward_log': 'False'}
            return output

    def kill_listener(self):
        if not self.http_process:
            output = {'outcome': 'failed', 'message': 'no listener is running', 'forward_log': 'False'}
            return output
        os.kill(self.http_process.pid, signal.SIGTERM)
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
                ['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', '/HTTPUploadExfil/HTTPUploadExfil.key',
                '-out', '/HTTPUploadExfil/HTTPUploadExfil.csr', '-days', '365', '-nodes', '-subj', f'{subj}'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            openssl_out = p.communicate()
            openssl_message = openssl_out[1].decode('utf-8')
            if 'problems making Certificate Request' in openssl_message:
                output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'True'}
                return output
            else:
                output = {'outcome': 'success', 'message': 'Certificate files written to /HTTPUploadExfil', 'forward_log': 'True'}
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
                shutil.copyfile(f'/etc/letsencrypt/live/{domain}/fullchain.pem', '/HTTPUploadExfil/HTTPUploadExfil.csr')
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            try:
                shutil.copyfile(f'/etc/letsencrypt/live/{domain}/privkey.pem', '/HTTPUploadExfil/HTTPUploadExfil.key')
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            output = {'outcome': 'success', 'message': 'Certificate files written to /HTTPUploadExfil', 'forward_log': 'True'}
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
