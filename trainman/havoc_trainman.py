import subprocess
from pathlib import Path

class Trainman:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None
        self.exec_process = None

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
        return True

    def execute_process(self):
        if 'file_path' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify file_name', 'forward_log': 'False'}
            return output
        file_path = Path(self.args['file_path'])
        if 'options' in self.args:
            cmd = self.args['options']
            if isinstance(cmd, list):
                cmd.insert(0, file_path)
                cmd.insert(0, 'bash')
            else:
                output = {'outcome': 'failed', 'message': 'options must be a list', 'forward_log': 'False'}
                return output
        else:
            cmd = ['bash', file_path]
        if file_path.is_file():
            self.exec_process = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        else:
            output = {'outcome': 'failed', 'message': 'file not found', 'forward_log': 'False'}
            return output

        if self.exec_process:
            output = {'outcome': 'success', 'message': 'file executed', 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'file execution failed', 'forward_log': 'True'}
        return output

    def get_process_output(self):
        if not self.exec_process:
            output = {'outcome': 'failed', 'message': 'no process is running', 'forward_log': 'False'}
            return output
        process_output = self.exec_process.stdout.read()
        output = {'outcome': 'success', 'process_output': process_output, 'forward_log': 'True'}
        return output

    def kill_process(self):
        if not self.exec_process:
            output = {'outcome': 'failed', 'message': 'no process is running', 'forward_log': 'False'}
            return output
        self.exec_process.terminate()
        output = {'outcome': 'success', 'message': 'process killed', 'forward_log': 'True'}
        return output

    def run_ad_dc(self):
        if 'domain' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify domain', 'forward_log': 'False'}
            return output
        domain = self.args['domain']
        if 'realm' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify realm', 'forward_log': 'False'}
            return output
        realm = self.args['realm']
        if 'admin_password' not in self.args:
            output = {
                'outcome': 'failed', 'message': 'instruct_args must specify admin_password', 'forward_log': 'False'
            }
            return output
        admin_password = self.args['admin_password']
        provision_cmd = f'samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL ' \
              f'--realm={realm} --domain={domain} --adminpass={admin_password}'
        provision = subprocess.Popen(
            provision_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        provision_output = provision.communicate()[0]
        if provision_output != 0:
            output = {
                'outcome': 'failed', 'message': 'AD provisioning failed. Check instruct_args', 'forward_log': 'False'
            }
        config_kerberos =  subprocess.Popen('cp /usr/local/samba/private/krb5.conf /etc/krb5.conf',
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                            )
        config_kerberos.communicate()
        self.exec_process = subprocess.Popen(
            'samba', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if self.exec_process:
            output = {'outcome': 'success', 'message': 'file executed', 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'file execution failed', 'forward_log': 'True'}
        return output


    def kill_ad_dc(self):
        if not self.exec_process:
            output = {'outcome': 'failed', 'message': 'no process is running', 'forward_log': 'False'}
            return output
        self.exec_process.terminate()
        output = {'outcome': 'success', 'message': 'process killed', 'forward_log': 'True'}
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
