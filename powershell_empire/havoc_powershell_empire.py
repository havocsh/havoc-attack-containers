import re
import time
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

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
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
                output = {'outcome': 'success', 'listeners': listeners, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': get_listeners_response.json(), 'forward_log': 'False'}
        else:
            get_listeners_uri = f'{self.server_uri}api/listeners?token={self.token}'
            get_listeners_response = requests.get(get_listeners_uri, verify=False)
            listeners = get_listeners_response.json()['listeners']
            output = {'outcome': 'success', 'listeners': listeners, 'forward_log': 'False'}
        return output

    def get_listener_options(self):
        if 'listener_type' in self.args:
            listener_type = self.args['listener_type']
            get_listener_options_uri = f'{self.server_uri}api/listeners/options/{listener_type}?token={self.token}'
            get_listener_options_response = requests.get(get_listener_options_uri, verify=False)
            if get_listener_options_response.status_code == 200:
                listener_options = get_listener_options_response.json()['listeneroptions']
                output = {'outcome': 'success', 'listener_options': listener_options, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': 'Check listener_type', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'Missing listener_type', 'forward_log': 'False'}
        return output

    def create_listener(self):
        if 'listener_type' in self.args:
            listener_type = self.args['listener_type']
            del self.args['listener_type']
        else:
            output = {'outcome': 'failed', 'message': 'Missing listener_type', 'forward_log': 'False'}
            return output
        if 'Name' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        create_listener_uri = f'{self.server_uri}api/listeners/{listener_type}?token={self.token}'
        create_listener_response = requests.post(create_listener_uri, json=self.args, verify=False)
        if create_listener_response.status_code == 200:
            message = create_listener_response.json()['success']
            output = {'outcome': 'success', 'message': message, 'forward_log': 'True'}
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
            output = {'outcome': 'success', 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': kill_listener_response.json(), 'forward_log': 'False'}
        return output

    def kill_all_listeners(self):
        kill_listener_uri = f'{self.server_uri}api/listeners/all?token={self.token}'
        requests.delete(kill_listener_uri, verify=False)
        output = {'outcome': 'success', 'forward_log': 'True'}
        return output

    def get_stagers(self):
        if 'Name' in self.args:
            stager_name = self.args['Name']
            get_stagers_uri = f'{self.server_uri}api/stagers/{stager_name}?token={self.token}'
            get_stagers_response = requests.get(get_stagers_uri, verify=False)
            if get_stagers_response.status_code == 200:
                stagers = get_stagers_response.json()['stagers']
                output = {'outcome': 'success', 'stagers': stagers, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': get_stagers_response.json(), 'forward_log': 'False'}
        else:
            get_stagers_uri = f'{self.server_uri}api/stagers?token={self.token}'
            get_stagers_response = requests.get(get_stagers_uri, verify=False)
            stagers = get_stagers_response.json()['stagers']
            output = {'outcome': 'success', 'stagers': stagers, 'forward_log': 'False'}
        return output

    def create_stager(self):
        if 'Listener' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing listener_name', 'forward_log': 'False'}
            return output
        if 'StagerName' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing StagerName', 'forward_log': 'False'}
            return output
        create_stager_uri = f'{self.server_uri}api/stagers?token={self.token}'
        create_stager_response = requests.post(create_stager_uri, json=self.args, verify=False)
        if create_stager_response.status_code == 200:
            output = {'outcome': 'success', 'stager': create_stager_response.json(), 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': create_stager_response.json(), 'forward_log': 'False'}
        return output

    def get_agents(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
            get_agents_uri = f'{self.server_uri}api/agents/{agent_name}?token={self.token}'
            get_agents_response = requests.get(get_agents_uri, verify=False)
            if get_agents_response.status_code == 200:
                agents = get_agents_response.json()['agents']
                output = {'outcome': 'success', 'agents': agents, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': get_agents_response.json(), 'forward_log': 'False'}
        else:
            get_agents_uri = f'{self.server_uri}api/agents?token={self.token}'
            get_agents_response = requests.get(get_agents_uri, verify=False)
            agents = get_agents_response.json()['agents']
            output = {'outcome': 'success', 'agents': agents, 'forward_log': 'False'}
        return output

    def get_stale_agents(self):
        get_stale_agents_uri = f'{self.server_uri}api/agents/stale?token={self.token}'
        get_stale_agents_response = requests.get(get_stale_agents_uri, verify=False)
        stale_agents = get_stale_agents_response.json()['agents']
        output = {'outcome': 'success', 'agents': stale_agents, 'forward_log': 'False'}
        return output

    def remove_agent(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        remove_agent_uri = f'{self.server_uri}api/agents/{agent_name}?token={self.token}'
        remove_agent_response = requests.delete(remove_agent_uri, verify=False)
        if remove_agent_response.status_code == 200:
            output = {'outcome': 'success', 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': remove_agent_response.json(), 'forward_log': 'False'}
        return output

    def remove_stale_agents(self):
        remove_stale_agents_uri = f'{self.server_uri}api/agents/stale?token={self.token}'
        requests.delete(remove_stale_agents_uri, verify=False)
        output = {'outcome': 'success', 'forward_log': 'True'}
        return output

    def agent_shell_command(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
            del self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        if 'command' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing command', 'forward_log': 'False'}
            return output
        agent_shell_uri = f'{self.server_uri}api/agents/{agent_name}/shell?token={self.token}'
        agent_shell_response = requests.post(agent_shell_uri, json=self.args, verify=False)
        if agent_shell_response.status_code == 200:
            results = None
            agent_info = None
            while not results:
                agent_results_uri = f'{self.server_uri}api/agents/{agent_name}/results?token={self.token}'
                agent_results_response = requests.get(agent_results_uri, verify=False)
                if 'results' in agent_results_response.json()['results']:
                    results = agent_results_response.json()['results']['results']
                if results:
                    requests.delete(agent_results_uri, verify=False)
                    get_agent_details_uri = f'{self.server_uri}api/agents/{agent_name}?token={self.token}'
                    get_agent_details_response = requests.get(get_agent_details_uri, verify=False)
                    if get_agent_details_response.status_code == 200:
                        agent_info = get_agent_details_response.json()['agents']
                else:
                    time.sleep(2)
        else:
            output = {'outcome': 'failed', 'message': agent_shell_response.json(), 'forward_log': 'False'}
            return output
        output = {'outcome': 'success', 'results': results, 'agent_info': agent_info, 'forward_log': 'True'}
        return output

    def clear_queued_shell_commands(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing agent_name', 'forward_log': 'False'}
            return output
        clear_queued_shell_commands_uri = f'{self.server_uri}api/agents/{agent_name}/clear?token={self.token}'
        clear_queued_shell_commands_response = requests.get(clear_queued_shell_commands_uri, verify=False)
        if clear_queued_shell_commands_response.status_code == 200:
            output = {'outcome': 'success', 'forward_log': 'True'}
            return output
        else:
            message = clear_queued_shell_commands_response.json()
            output = {'outcome': 'failed', 'message': message, 'forward_log': 'False'}
            return output

    def rename_agent(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
            del self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        if 'Newname' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing Newname', 'forward_log': 'False'}
            return output
        rename_agent_uri = f'{self.server_uri}api/agents/{agent_name}/rename?token={self.token}'
        rename_agent_response = requests.post(rename_agent_uri, json=self.args, verify=False)
        if rename_agent_response.status_code == 200:
            output = {'outcome': 'success', 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': rename_agent_response.json(), 'forward_log': 'False'}
            return output

    def kill_agent(self):
        if 'Name' in self.args:
            agent_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        kill_agent_uri = f'{self.server_uri}api/agents/{agent_name}/kill?token={self.token}'
        kill_agent_response = requests.get(kill_agent_uri, verify=False)
        if kill_agent_response.status_code == 200:
            output = {'outcome': 'success', 'forward_log': 'True'}
            return output
        else:
            output = {'outcome': 'failed', 'message': kill_agent_response.json(), 'forward_log': 'False'}
            return output

    def kill_all_agents(self):
        kill_all_agents_uri = f'{self.server_uri}api/agents/all/kill?token={self.token}'
        requests.get(kill_all_agents_uri, verify=False)
        output = {'outcome': 'success', 'forward_log': 'True'}
        return output

    def get_modules(self):
        if 'Name' in self.args:
            module_name = self.args['Name']
            get_modules_uri = f'{self.server_uri}api/modules/{module_name}?token={self.token}'
            get_modules_response = requests.get(get_modules_uri, verify=False)
            if get_modules_response.status_code == 200:
                modules = get_modules_response.json()['modules']
                output = {'outcome': 'success', 'modules': modules, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': get_modules_response.json(), 'forward_log': 'False'}
        else:
            get_modules_uri = f'{self.server_uri}api/modules?token={self.token}'
            get_modules_response = requests.get(get_modules_uri, verify=False)
            modules = get_modules_response.json()['modules']
            output = {'outcome': 'success', 'modules': modules, 'forward_log': 'False'}
        return output

    def search_modules(self):
        if 'term' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing term', 'forward_log': 'False'}
            return output
        search_modules_uri = f'{self.server_uri}api/modules/search?token={self.token}'
        search_modules_response = requests.post(search_modules_uri, json=self.args, verify=False)
        if 'modules' in search_modules_response.json():
            modules = search_modules_response.json()['modules']
            output = {'outcome': 'success', 'modules': modules, 'forward_log': 'False'}
            return output
        else:
            output = {'outcome': 'success', 'modules': 'No modules found', 'forward_log': 'False'}
            return output

    def execute_module(self):
        if 'Agent' in self.args:
            agent_name = self.args['Agent']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Agent', 'forward_log': 'False'}
            return output
        if 'Name' in self.args:
            module_name = self.args['Name']
        else:
            output = {'outcome': 'failed', 'message': 'Missing Name', 'forward_log': 'False'}
            return output
        execute_module_uri = f'{self.server_uri}api/modules/{module_name}?token={self.token}'
        execute_module_response = requests.post(execute_module_uri, json=self.args, verify=False)
        if execute_module_response.status_code == 200:
            results = None
            agent_info = None
            while not results:
                agent_results_uri = f'{self.server_uri}api/agents/{agent_name}/results?token={self.token}'
                agent_results_response = requests.get(agent_results_uri, verify=False)
                if 'results' in agent_results_response.json()['results']:
                    results = agent_results_response.json()['results']['results']
                if results:
                    requests.delete(agent_results_uri, verify=False)
                    get_agent_details_uri = f'{self.server_uri}api/agents/{agent_name}?token={self.token}'
                    get_agent_details_response = requests.get(get_agent_details_uri, verify=False)
                    if get_agent_details_response.status_code == 200:
                        agent_info = get_agent_details_response.json()['agents']
                else:
                    time.sleep(2)
        else:
            output = {'outcome': 'failed', 'message': execute_module_response.json(), 'forward_log': 'False'}
            return output
        output = {'outcome': 'success', 'results': results, 'agent_info': agent_info, 'forward_log': 'True'}
        return output

    def get_stored_credentials(self):
        get_stored_creds_uri = f'{self.server_uri}api/creds?token={self.token}'
        get_stored_creds_response = requests.get(get_stored_creds_uri, verify=False)
        stored_creds = get_stored_creds_response.json()['creds']
        output = {'outcome': 'success', 'credentials': stored_creds, 'forward_log': 'True'}
        return output

    def get_logged_events(self):
        if 'event_type' in self.args:
            event_type = self.args['event_type']
            get_logged_events_uri = f'{self.server_uri}api/reporting/type/{event_type}?token={self.token}'
            get_logged_events_response = requests.get(get_logged_events_uri, verify=False)
            if get_logged_events_response.status_code == 200:
                events = get_logged_events_response.json()['reporting']
                output = {'outcome': 'success', 'events': events, 'forward_log': 'False'}
            else:
                output = {'outcome': 'failed', 'message': 'Check event_type', 'forward_log': 'False'}
        else:
            get_logged_events_uri = f'{self.server_uri}api/reporting?token={self.token}'
            get_logged_events_response = requests.get(get_logged_events_uri, verify=False)
            events = get_logged_events_response.json()['reporting']
            output = {'outcome': 'success', 'events': events, 'forward_log': 'False'}
        return output

    def cert_gen(self):
        if 'subj' not in self.args:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify subj', 'forward_log': 'False'}
            return output
        subj = self.args['subj']

        p = subprocess.Popen(
            ['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', '/opt/Empire/empire/server/data/empire-priv.key',
             '-out', '/opt/Empire/empire/server/data/empire-chain.pem', '-days', '365', '-nodes', '-subj', f'{subj}'],
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
            self.event['agent_info'] = {}
            for k, v in self.event.items():
                self.event['agent_info'][k] = v
                del self.event[k]
        if 'agent_info' in self.event:
            agent_info = self.event['agent_info']
            if 'name' in agent_info:
                self.event['agent_name'] = agent_info['name']
            if 'external_ip' in agent_info:
                self.event['target_ip'] = agent_info['external_ip']
            if 'internal_ip' in agent_info:
                self.event['target_internal_ip'] = agent_info['internal_ip']
            if 'listener' in agent_info:
                match_listener = re.search('https?://([^:]+):?(\d+)?/', agent_info['listener'])
                if match_listener.group(1):
                    match_ip = re.search('\d+\.\d+\.\d+\.\d+', match_listener.group(1))
                    if match_ip:
                        self.event['callback_ip'] = match_listener.group(1)
                    else:
                        self.event['callback_hostname'] = match_listener.group(1)
                if match_listener.group(2):
                    self.event['callback_port'] = match_listener.group(2)
        return self.event