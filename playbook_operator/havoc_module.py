import re
import json
import dpath
import string
import random
import havoc
import havoc_functions
import hcl2
import networkx as nx
import boto3, botocore
import time as t
from datetime import datetime, timezone


def send_response(playbook_operator_response, forward_log, user_id, playbook_name, playbook_operator_version,
                  operator_command, command_args, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    output = {
        'command_output': playbook_operator_response, 'user_id': user_id, 'playbook_operator_version': playbook_operator_version, 
        'playbook_name': playbook_name, 'operator_command': operator_command, 'command_args': command_args, 'end_time': end_time,
        'forward_log': forward_log, 'timestamp': stime
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


class Action:

    def __init__(self):
        self.havoc_client = None
        self.action_dict = {
            'instruct_task': {},
            'download_from_workspace': {}, 
            'sync_to_workspace': {}, 
            'sync_from_workspace': {}, 
            'task_download_file': {}, 
            'task_execute_command': {}, 
            'execute_agent_module': {},
            'execute_agent_shell_command': {}
        }

    def instruct_task(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            instruct_command = object_parameters['instruct_command']
            instruct_args = object_parameters['instruct_args']
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            if not interact_with_task_response:
                return 'action_instruct_task_create_failed'
            self.action_dict['instruct_task'][object_name] = {key: value for key, value in object_parameters.items()}
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_instruct_task_create_failed'
                self.action_dict['instruct_task'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['instruct_task'][object_name]
        if action == 'delete':
            del self.action_dict['instruct_task'][object_name]
            return 'action_instruct_task_delete_completed'
        if action == 'read':
            new_path = re.search('action.instruct_task.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['instruct_task'], path)
        
    def download_from_workspace(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            instruct_command = 'download_from_workspace'
            instruct_args = {'file_name': object_parameters['file_name']}
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            if not interact_with_task_response:
                return 'action_download_from_workspace_create_failed'
            self.action_dict['download_from_workspace'][object_name] = {key: value for key, value in object_parameters.items()}
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_download_from_workspace_create_failed'
                self.action_dict['download_from_workspace'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['download_from_workspace'][object_name]
        if action == 'delete':
            task_name = object_parameters['task_name']
            instruct_command = 'del'
            instruct_args = {'file_name': object_parameters['file_name']}
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            if not interact_with_task_response:
                return 'action_download_from_workspace_delete_failed'
            del self.action_dict['download_from_workspace'][object_name]
            return 'action_download_from_workspace_delete_completed'
        if action == 'read':
            new_path = re.search('action.download_from_workspace.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['download_from_workspace'], path)
    
    def sync_to_workspace(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            instruct_command = 'sync_to_workspace'
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command)
            if not interact_with_task_response:
                return 'action_sync_to_workspace_create_failed'
            self.action_dict['sync_to_workspace'][object_name] = {key: value for key, value in object_parameters.items()}
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_sync_to_workspace_create_failed'
                self.action_dict['sync_to_workspace'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['sync_to_workspace'][object_name]
        if action == 'delete':
            del self.action_dict['sync_to_workspace'][object_name]
            return 'action_sync_to_workspace_delete_completed'
        if action == 'read':
            new_path = re.search('action.sync_to_workspace.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['sync_to_workspace'], path)
    
    def sync_from_workspace(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            instruct_command = 'sync_from_workspace'
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command)
            if not interact_with_task_response:
                return 'action_sync_from_workspace_create_failed'
            self.action_dict['sync_from_workspace'][object_name] = {key: value for key, value in object_parameters.items()}
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_sync_from_workspace_create_failed'
                self.action_dict['sync_from_workspace'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['sync_from_workspace'][object_name]
        if action == 'delete':
            del self.action_dict['sync_from_workspace'][object_name]
            return 'action_sync_from_workspace_delete_completed'
        if action == 'read':
            new_path = re.search('action.sync_from_workspace.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['sync_from_workspace'], path)
    
    def task_download_file(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            url = object_parameters['url']
            file_name = object_parameters['file_name']
            instruct_command = 'task_download_file'
            instruct_args = {'url': url, 'file_name': file_name}
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            if not interact_with_task_response:
                return 'action_task_download_file_create_failed'
            self.action_dict['task_download_file'][object_name] = {key: value for key, value in interact_with_task_response.items()}
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_task_download_file_create_failed'
                self.action_dict['task_download_file'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['task_download_file'][object_name]
        if action == 'delete':
            task_name = object_parameters['task_name']
            file_name = object_parameters['file_name']
            instruct_command = 'del'
            instruct_args = {'file_name': file_name}
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            del self.action_dict['task_download_file'][object_name]
            return 'action_task_download_file_delete_completed'
        if action == 'read':
            new_path = re.search('action.task_download_file.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['task_download_file'], path)
    
    def task_execute_command(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            command = object_parameters['command']
            instruct_command = 'task_execute_command'
            instruct_args = {'command': command}
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            if not interact_with_task_response:
                return 'action_task_execute_command_create_failed'
            self.action_dict['task_execute_command'][object_name] = {key: value for key, value in interact_with_task_response.items()}
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_task_execute_command_create_failed'
                self.action_dict['task_execute_command'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['task_execute_command'][object_name]
        if action == 'delete':
            task_name = object_parameters['task_name']
            command = object_parameters['command']
            instruct_command = 'kill_command'
            instruct_args = {'command': command}
            interact_with_task_response = self.havoc_client.interact_with_task(task_name, instruct_command, instruct_args=instruct_args)
            del self.action_dict['task_execute_command'][object_name]
            return 'action_task_execute_command_delete_completed'
        if action == 'read':
            new_path = re.search('action.task_execute_command.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['task_execute_command'], path)
    
    def execute_agent_module(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            agent_name = object_parameters['agent_name']
            module = object_parameters['module']
            wait_for_results = None
            beginning_string = None
            completion_string = None
            module_args = {}
            if 'wait_for_results' in object_parameters:
                wait_for_results = object_parameters['wait_for_results']
            if 'beginning_string' in object_parameters:
                beginning_string = object_parameters['beginning_string']
            if 'completion_string' in object_parameters:
                completion_string = object_parameters['completion_string']
            if 'module_args' in object_parameters:
                module_args = object_parameters['module_args']
            execute_agent_module_response = self.havoc_client.execute_agent_module(
                task_name, agent_name, module, module_args, wait_for_results=wait_for_results, beginning_string=beginning_string, completion_string=completion_string
            )
            if not execute_agent_module_response:
                return 'action_execute_agent_module_create_failed'
            self.action_dict['execute_agent_module'][object_name] = execute_agent_module_response
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_execute_agent_module_create_failed'
                self.action_dict['execute_agent_module'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['execute_agent_module'][object_name]
        if action == 'delete':
            del self.action_dict['execute_agent_module'][object_name]
            return 'action_execute_agent_module_delete_completed'
        if action == 'read':
            new_path = re.search('action.execute_agent_module.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['execute_agent_module'], path)
    
    def execute_agent_shell_command(self, object_name, action, **object_parameters):
        if action == 'create':
            if 'delay' in object_parameters:
                delay = object_parameters['delay']
                if isinstance(int(delay), int):
                    t.sleep(int(delay))
            task_name = object_parameters['task_name']
            agent_name = object_parameters['agent_name']
            command = object_parameters['command']
            wait_for_results = None
            beginning_string = None
            completion_string = None
            if 'wait_for_results' in object_parameters:
                wait_for_results = object_parameters['wait_for_results']
            if 'beginning_string' in object_parameters:
                beginning_string = object_parameters['beginning_string']
            if 'completion_string' in object_parameters:
                completion_string = object_parameters['completion_string']
            execute_agent_shell_command_response = self.havoc_client.execute_agent_shell_command(
                task_name, agent_name, command, wait_for_results=wait_for_results, beginning_string=beginning_string, completion_string=completion_string
            )
            if not execute_agent_shell_command_response:
                return 'action_execute_agent_shell_command_create_failed'
            self.action_dict['execute_agent_shell_command'][object_name] = execute_agent_shell_command_response
            if 'action_function' in object_parameters:
                for k in object_parameters['action_function'][0].keys():
                    called_action_function = k
                function_parameters = {}
                if object_parameters['action_function'][0][called_action_function]:
                    for k, v in object_parameters['action_function'][0][called_action_function][0].items():
                        function_parameters[k] = v
                action_function_response = havoc_functions.action_function(self.havoc_client, called_action_function, function_parameters)
                if 'failed' in action_function_response:
                    return 'action_execute_agent_shell_command_create_failed'
                self.action_dict['execute_agent_shell_command'][object_name][called_action_function] = {key: value for key, value in action_function_response.items()}
            return self.action_dict['execute_agent_shell_command'][object_name]
        if action == 'delete':
            del self.action_dict['execute_agent_shell_command'][object_name]
            return 'action_execute_agent_shell_command_delete_completed'
        if action == 'read':
            new_path = re.search('action.execute_agent_shell_command.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.action_dict['execute_agent_shell_command'], path)


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
            get_agent_response = self.havoc_client.get_agent(**object_parameters)
            if not get_agent_response:
                return 'data_agents_retrieve_failed'
            self.data_dict['agents'][object_name] = {key: value for key, value in get_agent_response.items()}
            return self.data_dict['agents'][object_name]
        if action == 'delete':
            del self.data_dict['agents'][object_name]
            return 'data_agents_deleted'
        if action == 'read':
            new_path = re.search('data.agents.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['agents'], path)
    
    def domains(self, object_name, action, **object_parameters):
        if action == 'create':
            get_domain_response = self.havoc_client.get_domain(**object_parameters)
            if not get_domain_response:
                return 'data_domains_retrieve_failed'
            self.data_dict['domains'][object_name] = {key: value for key, value in get_domain_response.items()}
            return self.data_dict['domains'][object_name]
        if action == 'delete':
            del self.data_dict['domains'][object_name]
            return 'data_domains_deleted'
        if action == 'read':
            new_path = re.search('data.domains.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['domains'], path)
    
    def files(self, object_name, action, **object_parameters):
        if action == 'create':
            get_file_response = self.havoc_client.get_file(**object_parameters)
            if not get_file_response:
                return 'data_files_retrieve_failed'
            self.data_dict['files'][object_name] = {key: value for key, value in get_file_response.items()}
            return self.data_dict['files'][object_name]
        if action == 'delete':
            del self.data_dict['files'][object_name]
            return 'data_files_deleted'
        if action == 'read':
            new_path = re.search('data.files.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['files'], path)
    
    def listeners(self, object_name, action, **object_parameters):
        if action == 'create':
            get_listener_response = self.havoc_client.get_listener(**object_parameters)
            if not get_listener_response:
                return 'data_listeners_retrieve_failed'
            self.data_dict['listeners'][object_name] = {key: value for key, value in get_listener_response.items()}
            return self.data_dict['listeners'][object_name]
        if action == 'delete':
            del self.data_dict['listeners'][object_name]
            return 'data_listeners_deleted'
        if action == 'read':
            new_path = re.search('data.listeners.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['listeners'], path)

    def portgroups(self, object_name, action, **object_parameters):
        if action == 'create':
            get_portgroup_response = self.havoc_client.get_portgroup(**object_parameters)
            if not get_portgroup_response:
                return 'data_portgroups_retrieve_failed'
            self.data_dict['portgroups'][object_name] = {key: value for key, value in get_portgroup_response.items()}
            return self.data_dict['portgroups'][object_name]
        if action == 'delete':
            del self.data_dict['portgroups'][object_name]
            return 'data_portgroups_deleted'
        if action == 'read':
            new_path = re.search('data.portgroups.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['portgroups'], path)
    
    def tasks(self, object_name, action, **object_parameters):
        if action == 'create':
            get_task_response = self.havoc_client.get_task(**object_parameters)
            if not get_task_response:
                return 'data_tasks_retrieve_failed'
            self.data_dict['tasks'][object_name] = {key: value for key, value in get_task_response.items()}
            return self.data_dict['tasks'][object_name]
        if action == 'delete':
            del self.data_dict['tasks'][object_name]
            return 'data_tasks_deleted'
        if action == 'read':
            new_path = re.search('data.tasks.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['tasks'], path)
    
    def task_types(self, object_name, action, **object_parameters):
        if action == 'create':
            get_task_type_response = self.havoc_client.get_task_type(**object_parameters)
            if not get_task_type_response:
                return 'data_task_types_retrieve_failed'
            self.data_dict['task_types'][object_name] = {key: value for key, value in get_task_type_response.items()}
            return self.data_dict['task_types'][object_name]
        if action == 'delete':
            del self.data_dict['task_types'][object_name]
            return 'data_task_types_deleted'
        if action == 'read':
            new_path = re.search('data.task_types.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.data_dict['task_types'], path)

class Local:
    
    def __init__(self):
        self.local_dict = {'function': {}}
    
    def function(self, object_name, action, **object_parameters):
        function_name = None
        function_parameters = []
        if action == 'create':
            function_name = object_parameters['function_name']
            if 'function_parameters' in object_parameters:
                function_parameters = object_parameters['function_parameters']
            result = havoc_functions.local_function(function_name, function_parameters)
            self.local_dict['function'][object_name] = result
            return result
        if action == 'delete':
            del self.local_dict['function'][object_name]
            return 'function_deleted'
        if action == 'read':
            new_path = re.search('local.function.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.local_dict['function'], path)


class Resource:
    
    def __init__(self):
        self.havoc_client = None
        self.resource_dict = {'file': {}, 'listener': {}, 'portgroup': {}, 'random_integer': {}, 'random_string': {}, 'task': {}}
    
    def file(self, object_name, action, **object_parameters):
        if action == 'create':
            file_name = object_parameters['file_name']
            file_contents = object_parameters['file_contents'].encode()
            create_file_response = self.havoc_client.create_file(file_name, file_contents)
            if not create_file_response:
                return 'resource_file_create_failed'
            if create_file_response['outcome'] != 'success':
                print(create_file_response)
                return 'resource_file_create_failed'
            self.resource_dict['file'][object_name] = {key: value for key, value in object_parameters.items()}
            return self.resource_dict['file'][object_name]
        if action == 'delete':
            delete_file_response = self.havoc_client.delete_file(**object_parameters)
            if not delete_file_response:
                return 'resource_file_delete_failed'
            del self.resource_dict['file'][object_name]
            return 'resource_file_deleted'
        if action == 'read':
            new_path = re.search('resource.file.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.resource_dict['file'], path)
    
    def listener(self, object_name, action, **object_parameters):
        if action == 'create':
            listener_name = object_parameters['listener_name']
            listener_type = object_parameters['listener_type']
            listener_port = object_parameters['listener_port']
            task_name = object_parameters['task_name']
            portgroups = object_parameters['portgroups']
            host_name = None
            domain_name = None
            if 'host_name' in object_parameters and 'domain_name' in object_parameters:
                host_name = object_parameters['host_name']
                domain_name = object_parameters['domain_name']
            create_listener_response = self.havoc_client.create_listener(
                listener_name=listener_name,
                listener_type=listener_type,
                listener_port=listener_port,
                task_name=task_name,
                portgroups=portgroups,
                host_name=host_name,
                domain_name=domain_name
            )
            if not create_listener_response:
                return 'resource_listener_create_failed'
            if create_listener_response['outcome'] != 'success':
                print(create_listener_response)
                return 'resource_listener_create_failed'
            self.resource_dict['listener'][object_name] = {key: value for key, value in create_listener_response.items()}
            return self.resource_dict['listener'][object_name]
        if action == 'delete':
            listener_name = self.resource_dict['listener'][object_name]['listener_name']
            delete_listener_response = self.havoc_client.delete_listener(listener_name=listener_name)
            if not delete_listener_response:
                return 'resource_listener_delete_failed'
            del self.resource_dict['listener'][object_name]
            return 'resource_listener_deleted'
        if action == 'read':
            new_path = re.search('resource.listener.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.resource_dict['listener'], path)

    def random_integer(self, object_name, action, **object_parameters):
        if action == 'create':
            self.resource_dict['random_integer'][object_name] = {key: value for key, value in object_parameters.items()}
            length = object_parameters['length']
            result = ''.join(random.choice(string.digits) for i in range(length))
            self.resource_dict['random_integer'][object_name]['result'] = result
            return self.resource_dict['random_integer'][object_name]
        if action == 'delete':
            del self.resource_dict['random_integer'][object_name]
            return 'resource_random_integer_deleted'
        if action == 'read':
            new_path = re.search('resource.random_integer.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.resource_dict['random_integer'], path)
    
    def random_string(self, object_name, action, **object_parameters):
        if action == 'create':
            self.resource_dict['random_string'][object_name] = {key: value for key, value in object_parameters.items()}
            length = object_parameters['length']
            if object_parameters['special']:
                string_seed = string.ascii_letters + string.punctuation
            else:
                string_seed = string.ascii_letters
            result = ''.join(random.choice(string_seed) for i in range(length))
            self.resource_dict['random_string'][object_name]['result'] = result
            return self.resource_dict['random_string'][object_name]
        if action == 'delete':
            del self.resource_dict['random_string'][object_name]
            return 'resource_random_string_deleted'
        if action == 'read':
            new_path = re.search('resource.random_string.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.resource_dict['random_string'], path)
    
    def portgroup(self, object_name, action, **object_parameters):
        if action == 'create':
            portgroup_name = object_parameters['portgroup_name']
            ip_ranges = object_parameters['ip_ranges']
            ip_protocol = object_parameters['ip_protocol']
            port = object_parameters['port']
            create_portgroup_response = self.havoc_client.create_portgroup(portgroup_name=portgroup_name, portgroup_description=f'Created by playbook operator.')
            if not create_portgroup_response:
                return 'resource_portgroup_create_failed'
            if create_portgroup_response['outcome'] != 'success':
                print(create_portgroup_response)
                return 'resource_portgroup_create_failed'
            update_portgroup_response = self.havoc_client.update_portgroup_rule(portgroup_name=portgroup_name, portgroup_action='add', ip_ranges=ip_ranges, ip_protocol=ip_protocol, port=port)
            if not update_portgroup_response:
                return 'resource_portgroup_create_failed'
            if update_portgroup_response['outcome'] != 'success':
                print(update_portgroup_response)
                return 'resource_portgroup_create_failed'
            get_portgroup_response = self.havoc_client.get_portgroup(portgroup_name=portgroup_name)
            self.resource_dict['portgroup'][object_name] = {key: value for key, value in get_portgroup_response.items()}
            return self.resource_dict['portgroup'][object_name]
        if action == 'delete':
            portgroup_name = self.resource_dict['portgroup'][object_name]['portgroup_name']
            delete_portgroup_response = self.havoc_client.delete_portgroup(portgroup_name=portgroup_name)
            if not delete_portgroup_response:
                return 'resource_portgroup_delete_failed'
            del self.resource_dict['portgroup'][object_name]
            return 'resource_portgroup_deleted'
        if action == 'read':
            new_path = re.search('resource.portgroup.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.resource_dict['portgroup'], path)
    
    def task(self, object_name, action, **object_parameters):
        if action == 'create':
            task_startup = {}
            task_startup['task_name'] = object_parameters['task_name']
            task_startup['task_type'] = object_parameters['task_type']
            if 'task_host_name' in object_parameters:
                task_startup['task_host_name'] = object_parameters['task_host_name']
            if 'task_domain_name' in object_parameters:
                task_startup['task_domain_name'] = object_parameters['task_domain_name']
            if 'portgroups' in object_parameters:
                task_startup['portgroups'] = object_parameters['portgroups']
            if 'end_time' in object_parameters:
                task_startup['end_time'] = object_parameters['end_time']
            task_startup_response = self.havoc_client.task_startup(**task_startup)
            if not task_startup_response:
                return 'resource_task_startup_failed'
            if 'task_status' not in task_startup_response:
                print(task_startup_response)
                return 'resource_task_startup_failed'
            self.resource_dict['task'][object_name] = {key: value for key, value in task_startup_response.items()}
            if 'listener' in object_parameters:
                self.resource_dict['task'][object_name]['listener'] = {}
                listener_args = {}
                listener_tls = None
                listener_type = None
                for k in object_parameters['listener'][0].keys():
                    if k != 'tls':
                        listener_type = k
                    else:
                        listener_tls = k
                if listener_tls:
                    tls_args = {}
                    for k, v in object_parameters['listener'][0][listener_tls][0].items():
                        tls_args[k] = v
                    cert_gen_response = self.havoc_client.interact_with_task(task_startup['task_name'], 'cert_gen', instruct_args=tls_args)
                    if not cert_gen_response:
                        return 'resource_listener_create_failed'
                    if cert_gen_response['outcome'] != 'success':
                        print(cert_gen_response)
                        return 'resource_listener_create_failed'
                listener_args['listener_type'] = listener_type
                listener_args['Name'] = listener_type
                for k, v in object_parameters['listener'][0][listener_type][0].items():
                    listener_args[k] = v
                create_listener_response = self.havoc_client.interact_with_task(task_startup['task_name'], 'create_listener', instruct_args=listener_args)
                if not create_listener_response:
                    return 'resource_listener_create_failed'
                if create_listener_response['outcome'] != 'success':
                    print(create_listener_response)
                    return 'resource_listener_create_failed'
                self.resource_dict['task'][object_name]['listener'] = create_listener_response['listener']
                if listener_tls:
                    self.resource_dict['task'][object_name]['listener']['tls'] = cert_gen_response['tls']
            if 'stager' in object_parameters:
                stager_args = {}
                for k, v in object_parameters['stager'][0].items():
                    stager_args[k] = v
                create_stager_response = self.havoc_client.interact_with_task(task_startup['task_name'], 'create_stager', instruct_args=stager_args)
                if not create_stager_response:
                    return 'resource_stager_create_failed'
                if create_stager_response['outcome'] != 'success':
                    print(create_stager_response)
                    return 'resource_stager_create_failed'
                self.resource_dict['task'][object_name]['stager'] = create_stager_response['stager']
            return self.resource_dict['task'][object_name]
        if action == 'delete':
            task_name = self.resource_dict['task'][object_name]['task_name']
            task_shutdown_response = self.havoc_client.task_shutdown(task_name)
            if 'completed' not in task_shutdown_response:
                return 'resource_task_delete_failed'
            del self.resource_dict['task'][object_name]
            return 'resource_task_deleted'
        if action == 'read':
            new_path = re.search('resource.task.(.*)', object_parameters['path'])
            path = re.sub('\.', '/', new_path.group(1))
            return dpath.get(self.resource_dict['task'], path)


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
            'download_from_workspace': self.action.download_from_workspace,
            'sync_to_workspace': self.action.sync_to_workspace,
            'sync_from_workspace': self.action.sync_from_workspace,
            'task_download_file': self.action.task_download_file,
            'task_execute_command': self.action.task_execute_command,
            'execute_agent_module': self.action.execute_agent_module,
            'execute_agent_shell_command': self.action.execute_agent_shell_command,
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
            'task': self.resource.task
        }
        object_def = object.split('.')
        method_name=object_def[1]
        object_name=object_def[2]
        return methods[method_name], object_name
    
    def creator(self, playbook_config, execution_list, executed_list):
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
                            executed_list.append(node_path)
                            method, object_name = self.object_resolver(node_path)
                            json_value = json.dumps(value)
                            dep_matches = re.findall('(\S+)\s+=\s+\${([^}]+)}', json_value)
                            if dep_matches:
                                for dep_match in dep_matches:
                                    if 'depends_on' not in dep_match.group(1):
                                        dep_method, dep_object = self.object_resolver(dep_match.group(2))
                                        dep_value = dep_method(dep_object, 'read', path=dep_match)
                                        re_sub = re.compile('\${' + dep_match + '}')
                                        json_value = re.sub(re_sub, dep_value, json_value)
                            value = json.loads(json_value, strict=False)
                            method_result = method(object_name, 'create', **value)
                            operator_command = f'create {node_path}'
                            if 'failed' not in method_result:
                                send_response({'outcome': 'success', 'details': method_result}, 'True', self.user_id, self.playbook_name, 
                                              self.playbook_operator_version, operator_command, value, self.end_time)
                            else:
                                send_response({'outcome': 'failed'}, 'True', self.user_id, self.playbook_name, self.playbook_operator_version,
                                              operator_command, value, self.end_time)
                                break
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
                        if execution_order == current_rule:
                            executed_list.remove(node_path)
                            method, object_name = self.object_resolver(node_path)
                            value = {'destroy_all_resources': True}
                            method_result = method(object_name, 'delete', **value)
                            operator_command = f'delete {node_path}'
                            if 'failed' not in method_result:
                                send_response({'outcome': 'success'}, 'True', self.user_id, self.playbook_name, self.playbook_operator_version,
                                              operator_command, value, self.end_time)
                            else:
                                send_response({'outcome': 'failed'}, 'True', self.user_id, self.playbook_name, self.playbook_operator_version,
                                              operator_command, value, self.end_time)
                            self.exec_order.prev_exec_rule(node_path)

    def execute_playbook(self):

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
                      self.playbook_operator_version, 'set_execution_order', {'no_args': 'True'}, self.end_time)
        self.exec_order.set_rules(execution_order, node_list)
        self.creator(playbook_config, node_list, tracking_list)

        execution_order = clean_dependencies(get_node_dependencies(DG, tracking_list))
        send_response({'outcome': 'success', 'details': execution_order}, 'True', self.user_id, self.playbook_name, 
                      self.playbook_operator_version, 'set_execution_order', {'no_args': 'True'}, self.end_time)
        self.exec_order.set_rules(execution_order, tracking_list)
        self.destroyer(playbook_config, tracking_list)

        output = {'outcome': 'success', 'message': 'playbook executed', 'forward_log': 'True'}
        return output

