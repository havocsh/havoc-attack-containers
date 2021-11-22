import os
import string
import random
import subprocess
from pathlib import Path
from shutil import copyfile

class Trainman:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None
        self.exec_process = None
        self.samba_process = None

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
        if 'user_name' not in self.args:
            output = {
                'outcome': 'failed', 'message': 'instruct_args must specify user_name', 'forward_log': 'False'
            }
            return output
        user_name = self.args['user_name']
        if 'user_password' not in self.args:
            output = {
                'outcome': 'failed', 'message': 'instruct_args must specify user_password', 'forward_log': 'False'
            }
            return output
        user_password = self.args['user_password']
        os.remove('/etc/samba/smb.conf')
        provision_cmd = [
            'samba-tool', 'domain', 'provision', '--server-role=dc', '--use-rfc2307', '--dns-backend=SAMBA_INTERNAL',
            f'--realm={realm.upper()}', f'--domain={domain}', f'--adminpass={admin_password}'
        ]
        provision = subprocess.Popen(
            provision_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        provision_output = provision.communicate()[0].decode('ascii')
        if provision_output:
            output = {'outcome': 'failed', 'message': provision_output, 'forward_log': 'False'}
            return output
        config_kerberos =  subprocess.Popen(['cp', '/var/lib/samba/private/krb5.conf', '/etc/krb5.conf'],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        config_kerberos.communicate()
        create_share_cmd = [
            'printf',
            '"\n[users]\n\tpath = /opt/havoc/users\n\tvalid users = @everybody\n\tforce group = +everybody\n\t'
            'writeable = yes\n\tcreate mask = 0666\n\tforce create mode = 0110\n\tdirectory mask = 0777"'
        ]
        with open('/etc/samba/smb.conf', 'a') as s_file:
            config_share_add = subprocess.Popen(create_share_cmd, stdout=s_file)
            config_share_add.communicate()
        s_file.close()
        self.samba_process = subprocess.Popen(
            ['samba'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if not self.samba_process:
            output = {'outcome': 'failed', 'message': 'running Samba AD DC failed', 'forward_log': 'True'}
            return output
        resolv_cmd = {'name_server': ['echo', 'nameserver 127.0.0.1'], 'search': ['echo', f'search {realm.lower()}']}
        with open('/etc/resolv.conf', 'w') as r_file:
            subprocess.Popen(resolv_cmd['name_server'], stdout=r_file)
        r_file.close()
        with open('/etc/resolv.conf', 'a') as r_file:
            subprocess.Popen(resolv_cmd['search'], stdout=r_file)
        r_file.close()
        split_ip = self.host_info[2].split('.')
        in_addr_arpa = f'{split_ip[3]}.{split_ip[2]}.{split_ip[1]}.{split_ip[0]}.in-addr.arpa'
        dns_zone_cmd = ['samba-tool', 'dns', 'zonecreate', realm.lower(), in_addr_arpa, '-U', 'Administrator',
                          '--password', admin_password]
        config_zone = subprocess.Popen(
            dns_zone_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        config_zone_output = config_zone.communicate()[0].decode('ascii')
        if config_zone_output:
            output = {'outcome': 'failed', 'message': config_zone_output, 'forward_log': 'False'}
            return output
        dns_add_cmd = ['samba-tool', 'dns', 'add', f'{self.host_info[1]}.{realm.lower()}', in_addr_arpa, '-U',
                       'Administrator', '--password', admin_password]
        config_dns_add = subprocess.Popen(
            dns_add_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        config_dns_add_output = config_dns_add.communicate()[0].decode('ascii')
        if config_dns_add_output:
            output = {'outcome': 'failed', 'message': config_dns_add_output, 'forward_log': 'False'}
            return output
        names_file = open('/opt/havoc/names.txt')
        names = names_file.readlines()
        names_file.close()
        name_count = 0
        while name_count <= 20:
            user_add_cmd = [
                'samba-tool', 'user', 'create', user_name, user_password,
                f'--home-directory=\\\\{self.host_info[1]}.{realm.lower()}\\users\\{user_name}',
            ]
            user_add = subprocess.Popen(
                user_add_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            user_add_output = user_add.communicate()[0].decode('ascii')
            if user_add_output:
                output = {'outcome': 'failed', 'message': user_add_output, 'forward_log': 'False'}
                return output
            if not os.path.exists(f'/opt/havoc/users/{user_name}'):
                os.makedirs(f'/opt/havoc/users/{user_name}')
            folder_perms_cmd = [
                'printf',
                f'"[{user_name}]\n\tpath = /opt/havoc/users/{user_name}\n\tvalid users = {user_name}\n\t'
                f'browseable = no"'
            ]
            with open('/etc/samba/smb.conf', 'a') as s_file:
                folder_perms_add = subprocess.Popen(folder_perms_cmd, stdin=s_file)
                folder_perms_add.communicate()
            s_file.close()
            copyfile('/opt/havoc/sample-data.csv', f'/opt/havoc/users/{user_name}/sample-data.csv')
            copyfile('/opt/havoc/test-5mb.bin', f'/opt/havoc/users/{user_name}/test-5mb.bin')
            name_count += 1
            initial = ''.join(random.choice(string.ascii_letters) for i in range(1)).lower()
            user_name = f'{initial}{names[random.randrange(999)].strip().lower()}'
        self.samba_process.terminate()
        self.samba_process = subprocess.Popen(
            ['samba'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if not self.samba_process:
            output = {'outcome': 'failed', 'message': 'running Samba AD DC failed', 'forward_log': 'True'}
            return output
        output = {'outcome': 'success', 'message': 'Samba AD DC is running', 'forward_log': 'True'}
        return output

    def kill_ad_dc(self):
        if not self.samba_process:
            output = {'outcome': 'failed', 'message': 'no Samba process is running', 'forward_log': 'False'}
            return output
        self.samba_process.terminate()
        output = {'outcome': 'success', 'message': 'Samba process killed', 'forward_log': 'True'}
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
