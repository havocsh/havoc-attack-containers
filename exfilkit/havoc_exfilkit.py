import subprocess

class call_exfilkit:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.dns_process = None
        self.http_get_process = None
        self.http_post_process = None

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
        return True

    def start_dns_exfil_server(self):
        if 'port' in self.args:
            port = self.args['port']
        else:
            output = {'outcome': 'failed', 'message': 'Missing port', 'forward_log': 'False'}
            return output
        if 'outfile' in self.args:
            outfile = f'/opt/havoc/shared/{self.args["outfile"]}'
        else:
            output = {'outcome': 'failed', 'message': 'Missing outfile', 'forward_log': 'False'}
            return output
        self.dns_process = subprocess.Popen(
            [
                '/exfilkit/exfilkit-cli.py',
                '-m exfilkit.methods.dns.subdomain_cipher.Server',
                f'-lp {port}',
                f'-o {outfile}'
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        std_out, std_err = self.dns_process.communicate()
        if self.dns_process.returncode == 0:
            output = {'outcome': 'success', 'message': 'dns_exfil_server is running', 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': std_err, 'forward_log': 'False'}
            return output

    def stop_dns_exfil_server(self):
        if not self.dns_process:
            output = {'outcome': 'failed', 'message': 'no dns_exfil_server is running', 'forward_log': 'False'}
            return output
        self.dns_process.terminate()
        output = {'outcome': 'success', 'message': 'dns_exfil_server stopped', 'forward_log': 'True'}
        return output

    def start_http_get_exfil_server(self):
        if 'port' in self.args:
            port = self.args['port']
        else:
            output = {'outcome': 'failed', 'message': 'Missing port', 'forward_log': 'False'}
            return output
        if 'outfile' in self.args:
            outfile = f'/opt/havoc/shared/{self.args["outfile"]}'
        else:
            output = {'outcome': 'failed', 'message': 'Missing outfile', 'forward_log': 'False'}
            return output
        self.http_get_process = subprocess.Popen(
            [
                '/exfilkit/exfilkit-cli.py',
                '-m exfilkit.methods.http.param_cipher.GETServer',
                f'-lp {port}',
                f'-o {outfile}'
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        std_out, std_err = self.http_get_process.communicate()
        if self.http_get_process.returncode == 0:
            output = {'outcome': 'success', 'message': 'http_get_exfil_server is running', 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': std_err, 'forward_log': 'False'}
            return output

    def stop_http_get_exfil_server(self):
        if not self.http_get_process:
            output = {'outcome': 'failed', 'message': 'no http_get_exfil_server is running', 'forward_log': 'False'}
            return output
        self.http_get_process.terminate()
        output = {'outcome': 'success', 'message': 'http_get_exfil_server stopped', 'forward_log': 'True'}
        return output

    def start_http_post_exfil_server(self):
        if 'port' in self.args:
            port = self.args['port']
        else:
            output = {'outcome': 'failed', 'message': 'Missing port', 'forward_log': 'False'}
            return output
        if 'outfile' in self.args:
            outfile = f'/opt/havoc/shared/{self.args["outfile"]}'
        else:
            output = {'outcome': 'failed', 'message': 'Missing outfile', 'forward_log': 'False'}
            return output
        self.http_post_process = subprocess.Popen(
            [
                '/exfilkit/exfilkit-cli.py',
                '-m exfilkit.methods.http.param_cipher.POSTServer',
                f'-lp {port}',
                f'-o {outfile}'
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        std_out, std_err = self.http_post_process.communicate()
        if self.http_post_process.returncode == 0:
            output = {'outcome': 'success', 'message': 'http_post_exfil_server is running', 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': std_err, 'forward_log': 'False'}
            return output

    def stop_http_post_exfil_server(self):
        if not self.http_post_process:
            output = {'outcome': 'failed', 'message': 'no http_post_exfil_server is running', 'forward_log': 'False'}
            return output
        self.http_post_process.terminate()
        output = {'outcome': 'success', 'message': 'http_post_exfil_server stopped', 'forward_log': 'True'}
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
