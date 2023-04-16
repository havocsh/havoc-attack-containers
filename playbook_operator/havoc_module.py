import re
import json
import copy
import dpath
import string
import random
import signal
import havoc
import havoc_functions
import hcl2
import networkx as nx
import boto3, botocore
import time as t
from datetime import datetime, timezone


def timeout_handler(signum, frame):
    raise Exception('timeout exceeded')

def send_response(playbook_operator_response, forward_log, user_id, playbook_name, playbook_operator_version,
                  operator_command, command_args, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    output = {
        'operator_command': operator_command, 'command_output': playbook_operator_response, 'user_id': user_id, 
        'playbook_operator_version': playbook_operator_version, 'playbook_name': playbook_name,
        'command_args': command_args, 'end_time': end_time, 'forward_log': forward_log, 'timestamp': stime
    }
    print(output)


class ExecutionOrder:

    def __init__(self):
        self.rules = None
        self.node_list = []
        self.current_rule = 0
    
    def set_rules(self, execution_order, node_list):
        self.rules = execution_order
        self.node_list = node_list
        return self.current_rule
    
    def get_exec_order(self, execution_object):
        for rule in self.rules:
            if execution_object == rule['rule_name']:
                return rule['exec_order'], self.current_rule
        return -1, self.current_rule
    
    def next_exec_rule(self, execution_object):
        temp_rule_list = []
        for rule in self.rules:
            if execution_object == rule['rule_name']:
                self.rules.remove(rule)
        for rule in self.rules:
            temp_rule_list.append(rule['exec_order'])
        if temp_rule_list:
            self.current_rule = min(temp_rule_list)
        return self.current_rule
    
    def prev_exec_rule(self, execution_object):
        temp_rule_list = []
        for rule in self.rules:
            if execution_object == rule['rule_name']:
                self.rules.remove(rule)
        for rule in self.rules:
            temp_rule_list.append(rule['exec_order'])
        if temp_rule_list:
            self.current_rule = max(temp_rule_list)
        return self.current_rule
    
    def exec_rule_failure(self, execution_list):
        temp_rule_list = []
        for rule in self.rules:
            if rule['rule_name'] not in execution_list:
                self.rules.remove(rule)
        for rule in self.rules:
            temp_rule_list.append(rule['exec_order'])
        if temp_rule_list:
            self.current_rule = max(temp_rule_list)
        return self.current_rule


class Action:

    def __init__(self):
        self.havoc_client = None
        self.action_dict = {'agent_action': {}, 'session_action': {}, 'task_action': {}}

    def agent_action(self, object_name, action, **object_parameters):
        if action == 'create':
            failed = None
            essential = None
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            if 'timeout' in object_parameters:
                timeout = object_parameters['timeout']
                signal.alarm(int(timeout))
            if 'essential' in object_parameters and object_parameters['essential'].lower() == 'true':
                essential = True
            try:
                task_name = object_parameters['task_name']
                agent_name = object_parameters['agent_name']
                agent_command = object_parameters['command']
                command_args = {}
                if agent_command in object_parameters:
                    command_args = object_parameters[agent_command]
                method = getattr(self.havoc_client, agent_command)
                agent_command_response = method(task_name, agent_name, **command_args)
            except Exception as e:
                if essential:
                    return f'action_agent_action_create_essential_failed: {e}'
                else:
                    failed = f'action_agent_action_create_failed: {e}'
            signal.alarm(0)
            if failed is None and agent_command_response['outcome'] == 'failed':
                if essential:
                    return f'action_agent_action_create_essential_failed: {agent_command_response}'
                else:
                    failed = f'action_agent_action_create_failed: {agent_command_response}'
            self.action_dict['agent_action'][object_name] = {key: value for key, value in object_parameters.items()}
            if failed is None:
                self.action_dict['agent_action'][object_name][agent_command] = agent_command_response[agent_command]
            if 'action_function' in object_parameters and failed is None:
                for k in object_parameters['action_function'].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][called_action_function]:
                    for k, v in object_parameters['action_function'][called_action_function].items():
                        if k != 'timeout':
                            function_parameters[k] = v
                if 'timeout' in object_parameters['action_function'][called_action_function]:
                    timeout = object_parameters['action_function'][called_action_function]['timeout']
                    signal.alarm(int(timeout))
                try:
                    action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                except Exception as e:
                    if essential:
                        return f'action_agent_action_create_essential_failed: {e}'
                    else:
                        failed = f'action_agent_action_create_failed: {e}'
                signal.alarm(0)
                if failed is None:
                    self.action_dict['agent_action'][object_name]['action_function'][called_action_function] = {key: value for key, value in action_function_response.items()}
            if failed is None:
                return self.action_dict['agent_action'][object_name]
            else:
                return failed
        if action == 'delete':
            try:
                agent_command = object_parameters['command']
                del self.action_dict['agent_action'][object_name]
                return f'action_agent_action_delete_completed'
            except Exception as e:
                return f'action_agent_action_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('action\.agent_action\.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.action_dict['agent_action'], path)
            except Exception as e:
                return f'action_agent_action_read_failed: {e}'

    def session_action(self, object_name, action, **object_parameters):
        if action == 'create':
            failed = None
            essential = None
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            if 'timeout' in object_parameters:
                timeout = object_parameters['timeout']
                signal.alarm(int(timeout))
            if 'essential' in object_parameters and object_parameters['essential'].lower() == 'true':
                essential = True
            try:
                task_name = object_parameters['task_name']
                session_id = object_parameters['session_id']
                session_command = object_parameters['command']
                command_args = {}
                if session_command in object_parameters:
                    command_args = object_parameters[session_command]
                method = getattr(self.havoc_client, session_command)
                session_command_response = method(task_name, session_id, **command_args)
            except Exception as e:
                if essential:
                    return f'action_session_action_create_essential_failed: {e}'
                else:
                    failed = f'action_session_action_create_failed: {e}'
            signal.alarm(0)
            if failed is None and session_command_response['outcome'] == 'failed':
                if essential:
                    return f'action_session_action_create_essential_failed: {session_command_response}'
                else:
                    failed = f'action_session_action_create_failed: {session_command_response}'
            self.action_dict['session_action'][object_name] = {key: value for key, value in object_parameters.items()}
            if failed is None:
                self.action_dict['session_action'][object_name][session_command] = session_command_response[session_command]
            if 'action_function' in object_parameters and failed is None:
                for k in object_parameters['action_function'].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][called_action_function]:
                    for k, v in object_parameters['action_function'][called_action_function].items():
                        if k != 'timeout':
                            function_parameters[k] = v
                if 'timeout' in object_parameters['action_function'][called_action_function]:
                    timeout = object_parameters['action_function'][called_action_function]['timeout']
                    signal.alarm(int(timeout))
                try:
                    action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                except Exception as e:
                    if essential:
                        return f'action_session_action_create_essential_failed: {e}'
                    else:
                        failed = f'action_session_action_create_failed: {e}'
                signal.alarm(0)
                if failed is None:
                    self.action_dict['session_action'][object_name]['action_function'][called_action_function] = {key: value for key, value in action_function_response.items()}
            if failed is None:
                return self.action_dict['session_action'][object_name]
            else:
                return failed
        if action == 'delete':
            try:
                session_command = object_parameters['command']
                del self.action_dict['session_action'][object_name]
                return f'action_session_action_delete_completed'
            except Exception as e:
                return f'action_session_action_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('action\.session_action\.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.action_dict['session_action'], path)
            except Exception as e:
                return f'action_session_action_read_failed: {e}'

    def task_action(self, object_name, action, **object_parameters):
        if action == 'create':
            failed = None
            essential = None
            instruct_args = None
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            if 'timeout' in object_parameters:
                timeout = object_parameters['timeout']
                signal.alarm(int(timeout))
            if 'essential' in object_parameters and object_parameters['essential'].lower() == 'true':
                essential = True
            try:
                task_name = object_parameters['task_name']
                instruct_command = object_parameters['command']
                instruct_instance = None
                if 'instruct_instance' in object_parameters:
                    instruct_instance = object_parameters['instruct_instance']
                instruct_args = {}
                if instruct_command in object_parameters:
                    instruct_args = object_parameters[instruct_command]
                interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_instance=instruct_instance, instruct_args=instruct_args)
            except Exception as e:
                if essential:
                    return f'action_task_action_create_essential_failed: {e}'
                else:
                    failed = f'action_task_action_create_failed: {e}'
            signal.alarm(0)
            if failed is None and interact_with_task_response['outcome'] == 'failed':
                if essential:
                    return f'action_task_action_create_essential_failed: {interact_with_task_response}'
                else:
                    failed = f'action_task_action_create_failed: {interact_with_task_response}'
            self.action_dict['task_action'][object_name] = {key: value for key, value in object_parameters.items()}
            if failed is None:
                self.action_dict['task_action'][object_name][instruct_command] = interact_with_task_response[instruct_command]
            if 'action_function' in object_parameters and failed is None:
                for k in object_parameters['action_function'].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][called_action_function]:
                    for k, v in object_parameters['action_function'][called_action_function].items():
                        if k != 'timeout':
                            function_parameters[k] = v
                if 'timeout' in object_parameters['action_function'][called_action_function]:
                    timeout = object_parameters['action_function'][called_action_function]['timeout']
                    signal.alarm(int(timeout))
                try:
                    action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                except Exception as e:
                    if essential:
                        return f'action_task_action_create_essential_failed: {e}'
                    else:
                        failed = f'action_task_action_create_failed: {e}'
                signal.alarm(0)
                if failed is None:
                    self.action_dict['task_action'][object_name]['action_function'][called_action_function] = {key: value for key, value in action_function_response.items()}
            if failed is None:
                return self.action_dict['task_action'][object_name]
            else:
                return failed
        if action == 'delete':
            try:
                instruct_command = object_parameters['command']
                del self.action_dict['task_action'][object_name]
                return f'action_task_action_delete_completed'
            except Exception as e:
                return f'action_task_action_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('action\.task_action\.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.action_dict['task_action'], path)
            except Exception as e:
                return f'action_task_action_read_failed: {e}'
            

class Data:
    
    def __init__(self):
        self.havoc_client = None
        self.data_dict = {
            'agents': {},
            'domains': {},
            'files': {},
            'listeners': {},
            'nodes': {},
            'portgroups': {},
            'tasks': {},
            'task_types': {}
        }
    
    def agents(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_agents_response = self.havoc_client.get_agents(**object_parameters)
            except Exception as e:
                return f'data_agents_create_failed: {e}'
            if get_agents_response['outcome'] == 'failed':
                return f'data_agents_create_failed: {get_agents_response}'
            self.data_dict['agents'][object_name] = {key: value for key, value in get_agents_response.items()}
            return self.data_dict['agents'][object_name]
        if action == 'delete':
            try:
                del self.data_dict['agents'][object_name]
                return 'data_agents_deleted'
            except Exception as e:
                return f'data_agents_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('data.agents.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.data_dict['agents'], path)
            except Exception as e:
                return f'data_agents_read_failed: {e}'
    
    def domains(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_domain_response = self.havoc_client.get_domain(**object_parameters)
            except Exception as e:
                return f'data_domains_create_failed: {e}'
            if get_domain_response['outcome'] == 'failed':
                return f'data_domains_create_failed: {get_domain_response}'
            self.data_dict['domains'][object_name] = {key: value for key, value in get_domain_response.items()}
            return self.data_dict['domains'][object_name]
        if action == 'delete':
            try:
                del self.data_dict['domains'][object_name]
                return 'data_domains_deleted'
            except Exception as e:
                return f'data_domains_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('data.domains.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.data_dict['domains'], path)
            except Exception as e:
                return f'data_domains_read_failed: {e}'
    
    def files(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_file_response = self.havoc_client.get_file(**object_parameters)
            except Exception as e:
                return f'data_files_create_failed: {e}'
            if get_file_response['outcome'] == 'failed':
                return f'data_files_create_failed: {get_file_response}'
            self.data_dict['files'][object_name] = {key: value for key, value in get_file_response.items()}
            return self.data_dict['files'][object_name]
        if action == 'delete':
            try:
                del self.data_dict['files'][object_name]
                return 'data_files_deleted'
            except Exception as e:
                return f'data_files_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('data.files.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.data_dict['files'], path)
            except Exception as e:
                return f'data_files_read_failed: {e}'
    
    def listeners(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_listener_response = self.havoc_client.get_listener(**object_parameters)
            except Exception as e:
                return f'data_listeners_create_failed: {e}'
            if get_listener_response['outcome'] == 'failed':
                return f'data_listeners_create_failed: {get_listener_response}'
            self.data_dict['listeners'][object_name] = {key: value for key, value in get_listener_response.items()}
            return self.data_dict['listeners'][object_name]
        if action == 'delete':
            try:
                del self.data_dict['listeners'][object_name]
                return 'data_listeners_deleted'
            except Exception as e:
                return f'data_listeners_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('data.listeners.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.data_dict['listeners'], path)
            except Exception as e:
                return f'data_listeners_read_failed: {e}'

    def portgroups(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_portgroup_response = self.havoc_client.get_portgroup(**object_parameters)
            except Exception as e:
                return f'data_portgroups_create_failed: {e}'
            if get_portgroup_response['outcome'] == 'failed':
                return f'data_portgroups_create_failed: {get_portgroup_response}'
            self.data_dict['portgroups'][object_name] = {key: value for key, value in get_portgroup_response.items()}
            return self.data_dict['portgroups'][object_name]
        if action == 'delete':
            try:
                del self.data_dict['portgroups'][object_name]
                return 'data_portgroups_deleted'
            except Exception as e:
                return f'data_portgroups_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('data.portgroups.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.data_dict['portgroups'], path)
            except Exception as e:
                return f'data_portgroups_read_failed: {e}'
    
    def tasks(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_task_response = self.havoc_client.get_task(**object_parameters)
            except Exception as e:
                return f'data_tasks_create_failed: {e}'
            if get_task_response['outcome'] == 'failed':
                return f'data_tasks_create_failed: {get_task_response}'
            self.data_dict['tasks'][object_name] = {key: value for key, value in get_task_response.items()}
            return self.data_dict['tasks'][object_name]
        if action == 'delete':
            del self.data_dict['tasks'][object_name]
            return 'data_tasks_deleted'
        if action == 'read':
            new_path = re.search('data.tasks.(.*)', object_parameters['path'])
            count_check = re.search('\[(\d+)\]', new_path.group(1))
            if count_check:
                new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
            else:
                new_path = new_path.group(1)
            path = re.sub('\.', '/', new_path)
            try:
                return dpath.get(self.data_dict['tasks'], path)
            except Exception as e:
                return f'data_tasks_read_failed: {e}'
    
    def task_types(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                get_task_type_response = self.havoc_client.get_task_type(**object_parameters)
            except Exception as e:
                return f'data_task_types_create_failed: {e}'
            if get_task_type_response['outcome'] == 'failed':
                return f'data_task_types_create_failed: {get_task_type_response}'
            self.data_dict['task_types'][object_name] = {key: value for key, value in get_task_type_response.items()}
            return self.data_dict['task_types'][object_name]
        if action == 'delete':
            try:
                del self.data_dict['task_types'][object_name]
                return 'data_task_types_deleted'
            except Exception as e:
                return f'data_task_types_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('data.task_types.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.data_dict['task_types'], path)
            except Exception as e:
                return f'data_task_types_read_failed: {e}'

class Local:
    
    def __init__(self):
        self.local_dict = {'function': {}}
    
    def function(self, object_name, action, **object_parameters):
        function_parameters = []
        if action == 'create':
            if 'function_parameters' in object_parameters:
                function_parameters = object_parameters['function_parameters']
            try:
                function_name = object_parameters['function_name']
                result = havoc_functions.local_function(function_name, function_parameters)
            except Exception as e:
                return f'function_create_failed: {e}'
            self.local_dict['function'][object_name] = result
            return result
        if action == 'delete':
            try:
                del self.local_dict['function'][object_name]
                return 'function_deleted'
            except Exception as e:
                return f'function_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('local.function.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.local_dict['function'], path)
            except Exception as e:
                return f'function_read_failed: {e}'


class Resource:
    
    def __init__(self):
        self.havoc_client = None
        self.resource_dict = {'file': {}, 'listener': {}, 'portgroup': {}, 'portgroup_rule': {}, 'random_integer': {}, 'random_string': {}, 'task': {}}
    
    def file(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                file_name = object_parameters['file_name']
                file_contents = object_parameters['file_contents'].encode()
                create_file_response = self.havoc_client.create_file(file_name, file_contents)
            except Exception as e:
                return f'resource_file_create_failed: {e}'
            if create_file_response['outcome'] == 'failed':
                return f'resource_file_create_failed: {create_file_response}'
            self.resource_dict['file'][object_name] = {key: value for key, value in object_parameters.items()}
            return self.resource_dict['file'][object_name]
        if action == 'delete':
            try:
                file_name = self.resource_dict['file'][object_name]['file_name']
                delete_file_response = self.havoc_client.delete_file(file_name=file_name)
            except Exception as e:
                return f'resource_file_delete_failed: {e}'
            if delete_file_response['outcome'] == 'failed':
                return f'resource_file_delete_failed: {delete_file_response}'
            del self.resource_dict['file'][object_name]
            return 'resource_file_deleted'
        if action == 'read':
            try:
                new_path = re.search('resource.file.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['file'], path)
            except Exception as e:
                return f'resource_file_read_failed: {e}'
    
    def listener(self, object_name, action, **object_parameters):
        if action == 'create':
            host_name = None
            domain_name = None
            if 'host_name' in object_parameters and 'domain_name' in object_parameters:
                host_name = object_parameters['host_name']
                domain_name = object_parameters['domain_name']
            try:
                listener_name = object_parameters['listener_name']
                listener_type = object_parameters['listener_type']
                listener_port = object_parameters['listener_port']
                task_name = object_parameters['task_name']
                portgroups = object_parameters['portgroups']
                create_listener_response = self.havoc_client.create_listener(
                    listener_name=listener_name,
                    listener_type=listener_type,
                    listener_port=listener_port,
                    task_name=task_name,
                    portgroups=portgroups,
                    host_name=host_name,
                    domain_name=domain_name
                )
            except Exception as e:
                return f'resource_listener_create_failed: {e}'
            if create_listener_response['outcome'] == 'failed':
                return f'resource_listener_create_failed: {create_listener_response}'
            self.resource_dict['listener'][object_name] = {key: value for key, value in create_listener_response.items()}
            return self.resource_dict['listener'][object_name]
        if action == 'delete':
            try:
                listener_name = self.resource_dict['listener'][object_name]['listener_name']
                delete_listener_response = self.havoc_client.delete_listener(listener_name=listener_name)
            except Exception as e:
                return f'resource_listener_delete_failed: {e}'
            if delete_listener_response['outcome'] == 'failed':
                return f'resource_listener_delete_failed: {delete_listener_response}'
            del self.resource_dict['listener'][object_name]
            return 'resource_listener_deleted'
        if action == 'read':
            try:
                new_path = re.search('resource.listener.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['listener'], path)
            except Exception as e:
                return f'resource_listener_read_failed: {e}'

    def random_integer(self, object_name, action, **object_parameters):
        if action == 'create':
            self.resource_dict['random_integer'][object_name] = {key: value for key, value in object_parameters.items()}
            try:
                length = object_parameters['length']
                result = ''.join(random.choice(string.digits) for i in range(length))
            except Exception as e:
                return f'resource_random_integer_create_failed: {e}'
            self.resource_dict['random_integer'][object_name]['result'] = result
            return self.resource_dict['random_integer'][object_name]
        if action == 'delete':
            try:
                del self.resource_dict['random_integer'][object_name]
                return 'resource_random_integer_deleted'
            except Exception as e:
                return f'resource_random_integer_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('resource.random_integer.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['random_integer'], path)
            except Exception as e:
                return f'resource_random_integer_read_failed: {e}'
    
    def random_string(self, object_name, action, **object_parameters):
        if action == 'create':
            self.resource_dict['random_string'][object_name] = {key: value for key, value in object_parameters.items()}
            string_seed = None
            if 'letters' in object_parameters:
                letters = object_parameters['letters']
                if isinstance(letters, str):
                    if letters.lower() == 'true':
                        string_seed = string.ascii_letters
                if isinstance(letters, bool):
                    if letters is True:
                        string_seed = string.ascii_letters
            if 'digits' in object_parameters:
                digits = object_parameters['digits']
                if isinstance(digits, str):
                    if digits.lower() == 'true':
                        string_seed = string_seed + string.digits
                if isinstance(digits, bool):
                    if digits is True:
                        string_seed = string_seed + string.digits
            if 'punctuation' in object_parameters:
                punctuation = object_parameters['punctuation']
                if isinstance(punctuation, str):
                    if punctuation.lower() == 'true':
                        string_seed = string_seed + string.punctuation
                if isinstance(punctuation, bool):
                    if punctuation is True:
                        string_seed = string_seed + string.punctuation
            if 'upper' in object_parameters:
                upper_val = object_parameters['upper']
                if isinstance(upper_val, str):
                    if upper_val.lower() == 'true':
                        string_seed = string_seed.upper()
                if isinstance(upper_val, bool):
                    if upper_val is True:
                        string_seed = string_seed.upper()
            if 'lower' in object_parameters:
                lower_val = object_parameters['lower']
                if isinstance(lower_val, str):
                    if lower_val.lower() == 'true':
                        string_seed = string_seed.lower()
                if isinstance(lower_val, bool):
                    if lower_val is True:
                        string_seed = string_seed.lower()
            if string_seed is None:
                string_seed = string.ascii_letters
            try:
                length = object_parameters['length']
                result = ''.join(random.choice(string_seed) for i in range(length))
            except Exception as e:
                return f'resource_random_string_create_failed: {e}'
            self.resource_dict['random_string'][object_name]['result'] = result
            return self.resource_dict['random_string'][object_name]
        if action == 'delete':
            try:
                del self.resource_dict['random_string'][object_name]
                return 'resource_random_string_deleted'
            except Exception as e:
                return f'resource_random_string_delete_failed: {e}'
        if action == 'read':
            try:
                new_path = re.search('resource.random_string.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['random_string'], path)
            except Exception as e:
                return f'resource_random_string_read_failed: {e}'
    
    def portgroup(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                portgroup_name = object_parameters['portgroup_name']
                create_portgroup_response = self.havoc_client.create_portgroup(portgroup_name=portgroup_name, portgroup_description=f'Created by playbook operator.')
            except Exception as e:
                return f'resource_portgroup_create_failed: {e}'
            if create_portgroup_response['outcome'] == 'failed':
                return f'resource_portgroup_create_failed: {create_portgroup_response}'
            self.resource_dict['portgroup'][object_name] = {}
            self.resource_dict['portgroup'][object_name]['portgroup_name'] = portgroup_name
            return self.resource_dict['portgroup'][object_name]
        if action == 'delete':
            try:
                portgroup_name = self.resource_dict['portgroup'][object_name]['portgroup_name']
                delete_portgroup_response = self.havoc_client.delete_portgroup(portgroup_name=portgroup_name)
            except Exception as e:
                return f'resource_portgroup_delete_failed: {e}'
            if delete_portgroup_response['outcome'] == 'failed':
                return f'resource_portgroup_delete_failed: {delete_portgroup_response}'
            del self.resource_dict['portgroup'][object_name]
            return 'resource_portgroup_deleted'
        if action == 'read':
            try:
                new_path = re.search('resource.portgroup.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['portgroup'], path)
            except Exception as e:
                return f'resource_portgroup_read_failed: {e}'
    
    def portgroup_rule(self, object_name, action, **object_parameters):
        if action == 'create':
            try:
                pg_name = object_parameters['portgroup_name']
                pg_action = object_parameters['portgroup_action']
                ip_ranges = object_parameters['ip_ranges']
                ip_protocol = object_parameters['ip_protocol']
                port = object_parameters['port']
                pg_rule_response = self.havoc_client.update_portgroup_rule(portgroup_name=pg_name, portgroup_action=pg_action, ip_ranges=ip_ranges, ip_protocol=ip_protocol, port=port)
            except Exception as e:
                return f'resource_portgroup_rule_create_failed: {e}'
            if pg_rule_response['outcome'] == 'failed':
                if 'already exists' in pg_rule_response['message'] or 'does not exist' in pg_rule_response['message']:
                    self.resource_dict['portgroup_rule'][object_name] = {}
                    self.resource_dict['portgroup_rule'][object_name]['portgroup_name'] = pg_name
                    self.resource_dict['portgroup_rule'][object_name]['ip_ranges'] = ip_ranges
                    self.resource_dict['portgroup_rule'][object_name]['ip_protocol'] = ip_protocol
                    self.resource_dict['portgroup_rule'][object_name]['port'] = port
                    return self.resource_dict['portgroup_rule'][object_name]
                else:
                    return f'resource_portgroup_rule_create_failed: {pg_rule_response}'
            self.resource_dict['portgroup_rule'][object_name] = {}
            self.resource_dict['portgroup_rule'][object_name]['portgroup_name'] = pg_name
            self.resource_dict['portgroup_rule'][object_name]['ip_ranges'] = ip_ranges
            self.resource_dict['portgroup_rule'][object_name]['ip_protocol'] = ip_protocol
            self.resource_dict['portgroup_rule'][object_name]['port'] = port
            return self.resource_dict['portgroup_rule'][object_name]
        if action == 'delete':
            try:
                pg_name = self.resource_dict['portgroup_rule'][object_name]['portgroup_name']
                ip_ranges = self.resource_dict['portgroup_rule'][object_name]['ip_ranges']
                ip_protocol = self.resource_dict['portgroup_rule'][object_name]['ip_protocol']
                port = self.resource_dict['portgroup_rule'][object_name]['port']
                pg_rule_response = self.havoc_client.update_portgroup_rule(portgroup_name=pg_name, portgroup_action='remove', ip_ranges=ip_ranges, ip_protocol=ip_protocol, port=port)
            except Exception as e:
                return f'resource_portgroup_rule_delete_failed: {e}'
            if pg_rule_response['outcome'] == 'failed':
                if 'does not exist' in pg_rule_response['message']:
                    del self.resource_dict['portgroup_rule'][object_name]
                    return 'resource_portgroup_rule_deleted'
                else:
                    return f'resource_portgroup_rule_delete_failed: {pg_rule_response}'
            del self.resource_dict['portgroup_rule'][object_name]
            return 'resource_portgroup_rule_deleted'
        if action == 'read':
            try:
                new_path = re.search('resource.portgroup_rule.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['portgroup_rule'], path)
            except Exception as e:
                return f'resource_portgroup_rule_read_failed: {e}'
    
    def task(self, object_name, action, **object_parameters):
        if action == 'create':
            task_startup = {}
            if 'task_host_name' in object_parameters:
                task_startup['task_host_name'] = object_parameters['task_host_name']
            if 'task_domain_name' in object_parameters:
                task_startup['task_domain_name'] = object_parameters['task_domain_name']
            if 'portgroups' in object_parameters:
                task_startup['portgroups'] = object_parameters['portgroups']
            if 'end_time' in object_parameters:
                task_startup['end_time'] = object_parameters['end_time']
            try:
                task_startup['task_name'] = object_parameters['task_name']
                task_startup['task_type'] = object_parameters['task_type']
                task_startup_response = self.havoc_client.task_startup(**task_startup)
            except Exception as e:
                return f'resource_task_startup_failed: {e}'
            if task_startup_response['outcome'] == 'failed':
                return f'resource_task_startup_failed: {task_startup_response}'
            self.resource_dict['task'][object_name] = {key: value for key, value in task_startup_response.items()}
            if 'startup_actions' in object_parameters:
                for startup_action in object_parameters['startup_actions']:
                    self.resource_dict['task'][object_name][startup_action] = {}
                    instruct_instance = None
                    instruct_args = copy.deepcopy(object_parameters[startup_action])
                    if 'instruct_instance' in instruct_args:
                        instruct_instance = instruct_args['instruct_instance']
                        del instruct_args['instruct_instance']
                    try:
                        response = self.havoc_client.interact_with_task(task_startup['task_name'], startup_action, instruct_instance=instruct_instance, instruct_args=instruct_args)
                    except Exception as e:
                        self.havoc_client.task_shutdown(task_startup['task_name'])
                        return f'resource_task_{startup_action}_create_failed: {e}'
                    if response['outcome'] == 'failed':
                        self.havoc_client.task_shutdown(task_startup['task_name'])
                        return f'resource_task_{startup_action}_create_failed: {response}'
                    self.resource_dict['task'][object_name][startup_action] = response[startup_action]
            return self.resource_dict['task'][object_name]
        if action == 'delete':
            try:
                task_name = self.resource_dict['task'][object_name]['task_name']
                task_shutdown_response = self.havoc_client.task_shutdown(task_name)
            except Exception as e:
                return f'resource_task_delete_failed: {e}'
            if 'completed' not in task_shutdown_response:
                return f'resource_task_delete_failed: {task_shutdown_response}'
            del self.resource_dict['task'][object_name]
            return 'resource_task_deleted'
        if action == 'read':
            try:
                new_path = re.search('resource.task.(.*)', object_parameters['path'])
                count_check = re.search('\[(\d+)\]', new_path.group(1))
                if count_check:
                    new_path = re.sub('\[\d+\]', '.' + count_check.group(1), new_path.group(1))
                else:
                    new_path = new_path.group(1)
                path = re.sub('\.', '/', new_path)
                return dpath.get(self.resource_dict['task'], path)
            except Exception as e:
                return f'resource_task_read_failed: {e}'


class call_object():

    def __init__(self):
        self.exec_order = ExecutionOrder()
        self.action = Action()
        self.data = Data()
        self.local = Local()
        self.resource = Resource()
        self.region = None
        self.deployment_name = None
        self.user_id = None
        self.playbook_name = None
        self.playbook_operator_version = None
        self.args = None
        self.end_time = None
        self.__havoc_client = None
        self.__aws_s3_client = None
    
    @property
    def havoc_client(self):
        if self.__havoc_client is None:
            api_key = self.args['api_key']
            secret = self.args['secret']
            api_region = self.args['api_region']
            api_domain_name = self.args['api_domain_name']
            self.__havoc_client = havoc.Connect(api_region, api_domain_name, api_key, secret, api_version=1)
        return self.__havoc_client
    
    @property
    def aws_s3_client(self):
        """Returns the boto3 S3 session (establishes one automatically if one does not already exist)"""
        if self.__aws_s3_client is None:
            self.__aws_s3_client = boto3.client('s3', region_name=self.region)
        return self.__aws_s3_client

    def set_args(self, region, deployment_name, user_id, playbook_name, playbook_operator_version, command_args, end_time):
        self.region = region
        self.deployment_name = deployment_name
        self.user_id = user_id
        self.playbook_name = playbook_name
        self.playbook_operator_version = playbook_operator_version
        self.args = command_args
        self.end_time = end_time
        return True

    def object_resolver(self, object):
        methods = {
            'agent_action': self.action.agent_action,
            'session_action': self.action.session_action,
            'task_action': self.action.task_action,
            'agents': self.data.agents,
            'domains': self.data.domains,
            'files': self.data.files,
            'listeners': self.data.listeners,
            'portgroups': self.data.portgroups,
            'tasks': self.data.tasks,
            'task_types': self.data.task_types,
            'function': self.local.function,
            'file': self.resource.file,
            'listener': self.resource.listener,
            'random_integer': self.resource.random_integer,
            'random_string': self.resource.random_string,
            'portgroup': self.resource.portgroup,
            'portgroup_rule': self.resource.portgroup_rule,
            'task': self.resource.task
        }
        object_def = object.split('.')
        method_name=object_def[1]
        object_name=object_def[2]
        return methods[method_name], object_name
    
    def creator(self, playbook_config, execution_list, executed_list):

        # Remove depends_on references from playbook_config
        depends_on_list = []
        for (path, value) in dpath.search(playbook_config, '*/*/*/*/*', yielded=True):
            if 'depends_on' in path:
                depends_on_list.append(path)
        for depends_on in depends_on_list:
            dpath.delete(playbook_config, depends_on)
        
        # Proceed with block processing
        while execution_list:
            for section in playbook_config:
                for (path, value) in dpath.search(playbook_config[section], '*/*/*', yielded=True):
                    new_path = re.search('\d+/(.*)', path).group(1)
                    dot_path = re.sub('/', '.', new_path)
                    node_path = f'{section}.{dot_path}'
                    if node_path in execution_list:
                        execution_order, current_rule = self.exec_order.get_exec_order(node_path)
                        if execution_order == current_rule:
                            execution_list.remove(node_path)
                            method, object_name = self.object_resolver(node_path)
                            json_value = json.dumps(value)
                            dep_matches = re.findall('\${([^}]+)}', json_value)
                            if dep_matches:
                                for dep_match in dep_matches:
                                    dep_method, dep_object = self.object_resolver(dep_match)
                                    dep_value = dep_method(dep_object, 'read', path=dep_match)
                                    if not isinstance(dep_value, str) and not isinstance(dep_value, int):
                                        dep_value_type = type(dep_value)
                                        send_response({'outcome': 'failed', 'details': f'{dep_match} returned {dep_value_type}: must be str or int'},
                                                      'True', self.user_id, self.playbook_name, self.playbook_operator_version, f'configure {node_path}',
                                                      value, self.end_time)
                                        return node_path
                                    re_sub = re.compile('\${' + re.escape(dep_match) + '}')
                                    json_value = re.sub(re_sub, str(dep_value), json_value)
                            send_response({'outcome': 'success', 'details': json_value}, 'True', self.user_id,
                                          self.playbook_name, self.playbook_operator_version, f'configure {node_path}', value, self.end_time)
                            t.sleep(5)
                            value = json.loads(json_value, strict=False)
                            operator_command = f'create {node_path}'
                            method_result = method(object_name, 'create', **value)
                            if 'failed' not in method_result:
                                send_response({'outcome': 'success', 'details': method_result}, 'True', self.user_id,
                                              self.playbook_name, self.playbook_operator_version, operator_command, value, self.end_time)
                                executed_list.append(node_path)
                                t.sleep(5)
                            if 'failed' in method_result:
                                send_response({'outcome': 'failed', 'details': method_result}, 'True', self.user_id, self.playbook_name,
                                              self.playbook_operator_version, operator_command, value, self.end_time)
                                if 'action' in method_result and 'essential' in method_result:
                                    return node_path
                                if 'action' not in method_result:
                                    return node_path
                                executed_list.append(node_path)
                                t.sleep(5)
                            self.exec_order.next_exec_rule(node_path)
                        
    def destroyer(self, playbook_config, executed_list):
        while executed_list:
            for section in playbook_config:
                for (path, value) in dpath.search(playbook_config[section], '*/*/*', yielded=True):
                    new_path = re.search('\d+/(.*)', path).group(1)
                    dot_path = re.sub('/', '.', new_path)
                    node_path = f'{section}.{dot_path}'
                    if node_path in executed_list:
                        execution_order, current_rule = self.exec_order.get_exec_order(node_path)
                        t.sleep(5)
                        if execution_order == current_rule:
                            executed_list.remove(node_path)
                            method, object_name = self.object_resolver(node_path)
                            value = {'destroy_all_resources': True}
                            send_response({'outcome': 'success'}, 'True', self.user_id, self.playbook_name,
                                          self.playbook_operator_version, f'configure {node_path}', value, self.end_time)
                            t.sleep(5)
                            operator_command = f'delete {node_path}'
                            method_result = method(object_name, 'delete', **value)
                            if 'failed' not in method_result:
                                send_response({'outcome': 'success', 'details': method_result}, 'True', self.user_id, self.playbook_name,
                                              self.playbook_operator_version, operator_command, value, self.end_time)
                                t.sleep(5)
                            else:
                                send_response({'outcome': 'failed', 'details': method_result}, 'True', self.user_id, self.playbook_name,
                                              self.playbook_operator_version, operator_command, value, self.end_time)
                                t.sleep(5)
                            self.exec_order.prev_exec_rule(node_path)

    def execute_playbook(self):

        # Set signal handler to manage method call timeouts
        signal.signal(signal.SIGALRM, timeout_handler)

        self.action.havoc_client = self.havoc_client
        self.data.havoc_client = self.havoc_client
        self.resource.havoc_client = self.havoc_client

        def download_playbook():
            config_pointer = self.args['config_pointer']
            try:
                get_object_response = self.aws_s3_client.get_object(
                    Bucket=f'{self.deployment_name}-playbooks',
                    Key=config_pointer
                )
                playbook_config = get_object_response['Body'].read()
            except botocore.exceptions.ClientError as error:
                return error
            except botocore.exceptions.ParamValidationError as error:
                return error
            return playbook_config

        # Add nodes to graph
        def afilter(x):
            if re.match('{([^}]+)}', str(x)):
                    return True
            return False

        def add_dependency_edges(block, parent):
            for (path, value) in dpath.search(block, '*/*/*', afilter=afilter, yielded=True):
                matches = re.findall('\${([^}]+)}', json.dumps(value))
                for match in matches:
                    dep = re.search('([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', match)
                    if dep:
                        new_path = re.search('\d+/(.*)', path).group(1)
                        dot_path = re.sub('/', '.', new_path)
                        node_path = f'{parent}.{dot_path}'
                        DG.add_edge(dep.group(1), node_path)

        def get_node_dependencies(graph, start_nodes):
            nodes = [(x, 0) for x in start_nodes]
            for node, depth in nodes:
                this_depth = depth - 1
                for prenode in graph.predecessors(node):
                    nodes.append((prenode, this_depth))
            return nodes

        def clean_dependencies(dependencies):
            dependencies = set(dependencies)
            dep_depth_map = {}
            max_depth = 0
            for node, depth in dependencies:
                dep_depth_map.setdefault(node, []).append(depth)
                max_depth = min(depth, max_depth)   
            dep_depth_map = sorted(dep_depth_map.items(), key=lambda x: min(x[1]))
            return [{"rule_name": node, "exec_order": min(depth) + abs(max_depth)} for node, depth in dep_depth_map]

        playbook_config_source = download_playbook()
        try:
            playbook_config = json.loads(playbook_config_source)
        except:
            pass
        if not playbook_config:
            playbook_config = hcl2.load(playbook_config_source)

        DG = nx.DiGraph()
        action_blocks = None
        data_blocks = None
        local_blocks = None
        resource_blocks = None

        if 'action' in playbook_config:
            action_blocks = playbook_config['action']
            add_dependency_edges(action_blocks, 'action')

        if 'data' in playbook_config:
            data_blocks = playbook_config['data']
            add_dependency_edges(data_blocks, 'data')

        if 'local' in playbook_config:
            local_blocks = playbook_config['local']
            add_dependency_edges(local_blocks, 'local')

        if 'resource' in playbook_config:
            resource_blocks = playbook_config['resource']
            add_dependency_edges(resource_blocks, 'resource')

        node_list = []
        tracking_list = []
        for node in DG.nodes:
            node_list.append(node)
        execution_order = clean_dependencies(get_node_dependencies(DG, node_list))
        send_response({'outcome': 'success', 'details': execution_order}, 'True', self.user_id, self.playbook_name, 
                      self.playbook_operator_version, 'create execution order', {'no_args': 'True'}, self.end_time)
        self.exec_order.set_rules(execution_order, node_list)
        t.sleep(5)
        creator_result = self.creator(playbook_config, node_list, tracking_list)

        execution_order = clean_dependencies(get_node_dependencies(DG, tracking_list))
        send_response({'outcome': 'success', 'details': execution_order}, 'True', self.user_id, self.playbook_name, 
                      self.playbook_operator_version, 'delete execution order', {'no_args': 'True'}, self.end_time)
        self.exec_order.set_rules(execution_order, tracking_list)
        if creator_result:
            self.exec_order.exec_rule_failure(tracking_list)
        t.sleep(5)
        self.destroyer(playbook_config, tracking_list)

        return {'outcome': 'success', 'message': 'playbook execution completed', 'forward_log': 'True'}
