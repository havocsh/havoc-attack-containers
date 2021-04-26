#!/usr/bin/python3

import os
import re
import sys
import json
import boto3
import socket
import requests
import subprocess
from datetime import datetime, timezone
from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, Deferred

# Havoc Imports
import havoc_metasploit


class Remote:
    def __init__(self, api_key, secret_key, remote_api_endpoint, manage_api_endpoint):
        self.api_key = api_key
        self.secret_key = secret_key
        self.remote_api_endpoint = remote_api_endpoint
        self.manage_api_endpoint = manage_api_endpoint
        self.__check = None
        self.__connection_params = None

    @property
    def check(self):
        if self.api_key and self.secret_key and self.remote_api_endpoint and self.manage_api_endpoint:
            self.__check = True
        return self.__check

    @property
    def connection_params(self):
        if self.api_key and self.secret_key and self.remote_api_endpoint and self.manage_api_endpoint:
            self.__connection_params = [
                self.api_key,
                self.secret_key,
                self.remote_api_endpoint,
                self.manage_api_endpoint
            ]
        return self.__connection_params


def sleep(delay):
    d = Deferred()
    reactor.callLater(delay, d.callback, None)
    return d


def shutdown_timer(end_time):
    timestamp = datetime.strptime(end_time, "%m/%d/%Y %H:%M:%S %z")
    if datetime.now(timezone.utc) >= timestamp:
        return True


def get_commands_s3(client, campaign_id, task_name, command_list):
    list_objects_response = client.list_objects_v2(
        Bucket=f'{campaign_id}-workspace',
        Prefix=task_name + '/'
    )
    assert list_objects_response, f'list_objects_v2 failed for task_name {task_name}'
    file_list = []
    regex = f'{task_name}/(.*)'
    if 'Contents' in list_objects_response:
        for file_object in list_objects_response['Contents']:
            search = re.search(regex, file_object['Key'])
            if search.group(1):
                file_list.append(file_object['Key'])
        for file_entry in file_list:
            get_object_response = client.get_object(
                Bucket=f'{campaign_id}-workspace',
                Key=file_entry
            )
            assert get_object_response, f'get_object failed for task_name {task_name}, key {file_entry}'
            interaction = json.loads(get_object_response['Body'].read().decode('utf-8'))
            interaction['timestamp'] = datetime.now()
            command_list.append(interaction)
            delete_object_response = client.delete_object(
                Bucket=f'{campaign_id}-workspace',
                Key=file_entry
            )
            assert delete_object_response, f"delete_object failed for task {task_name}, key {file_entry}"


def get_commands_http(rt, task_name, command_list):
    api_key = rt.connection_params[0]
    secret_key = rt.connection_params[1]
    api_endpoint = rt.connection_params[2]
    api_headers = {'x-api-key': api_key, 'x-secret-key': secret_key}
    api_json = {'command': 'get_commands', 'detail': {'task_name': task_name}}

    commands_response = requests.post(api_endpoint, headers=api_headers, json=api_json)
    assert commands_response, f"request to api_endpoint {api_endpoint} failed for task {task_name}"

    for command in json.loads(commands_response.text)['commands']:
        command_list.append(command)


def post_response_http(rt, results):
    api_key = rt.connection_params[0]
    secret_key = rt.connection_params[1]
    api_endpoint = rt.connection_params[2]
    api_headers = {'x-api-key': api_key, 'x-secret-key': secret_key}
    api_json = {'command': 'post_results', 'results': results}

    post_response = requests.post(api_endpoint, headers=api_headers, json=api_json)
    assert post_response, f"request to api_endpoint {api_endpoint} failed for results {results}"


def sync_workspace_http(rt, sync_direction):
    api_key = rt.connection_params[0]
    secret_key = rt.connection_params[1]
    api_endpoint = rt.connection_params[3]
    api_headers = {'x-api-key': api_key, 'x-secret-key': secret_key}
    file_list = []
    if sync_direction == 'sync_from_workspace':
        api_json = {'resource': 'workspace', 'command': 'list'}
        list_response = requests.post(api_endpoint, headers=api_headers, json=api_json)
        list_body = json.loads(list_response.text)['body']
        for file in list_body['files']:
            file_list.append(file)
            api_json = {'resource': 'workspace', 'command': 'get', 'detail': {'filename': file}}
            get_file_response = requests.post(api_endpoint, headers=api_headers, json=api_json)
            get_file_body = json.loads(get_file_response.text)['body']
            file_contents = get_file_body['file_contents']
            f = open(f'/opt/havoc/shared/{file}', 'wb')
            f.write(file_contents)
            f.close()
    if sync_direction == 'sync_to_workspace':
        for root, subdirs, files in os.walk('/opt/havoc/shared'):
            for filename in files:
                corrected_root = re.match('/opt/havoc/shared/(.*)', root).group(1)
                relative_path = os.path.join(corrected_root, filename)
                file_list.append(relative_path)
                file_path = os.path.join(root, filename)
                f = open(file_path, 'rb')
                file_contents = f.read()
                f.close()
                api_json = {
                    'resource': 'workspace', 'command': 'create', 'detail': {
                        'filename': relative_path, 'file_contents': file_contents
                    }
                }
                requests.post(api_endpoint, headers=api_headers, json=api_json)
    return file_list


def build_response(task_response, forward_log, user_id, task_name, task_context, task_type, interactive,
                   instruct_user, instruct_instance, instruct_command, instruct_args, attack_ip, connection_id,
                   end_time):
    output = {
        'task_response': task_response, 'user_id': user_id, 'task_name': task_name, 'task_context': task_context,
        'task_type': task_type, 'interactive': interactive, 'instruct_user': instruct_user,
        'instruct_instance': instruct_instance, 'instruct_command': instruct_command, 'instruct_args': instruct_args,
        'attack_ip': attack_ip, 'end_time': end_time, 'connection_id': connection_id, 'forward_log': forward_log
    }
    return output


@inlineCallbacks
def action(campaign_id, user_id, task_type, task_name, task_context, rt, end_time, command_list, attack_ip, hostname,
           local_ip):
    call_function = None
    metasploit = {}
    while True:

        def sortFunc(e):
            return e['timestamp']

        command_list.sort(key=sortFunc)
        for c in command_list:
            connection_id = c['connection_id']
            interactive = c['interactive']
            instruct_user = c['instruct_user']
            instruct_instance = c['instruct_instance']
            instruct_command = c['instruct_command']
            instruct_args = c['instruct_args']
            if 'end_time' in c:
                end_time = c['end_time']
            shutdown = None
            if end_time != 'None':
                shutdown = shutdown_timer(end_time)
            if instruct_command == 'Initialize' or instruct_command == 'sync_from_workspace':
                if not rt.check:
                    file_list = []
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "s3", "sync",
                                     f"s3://{campaign_id}-workspace/shared", "/opt/havoc/shared/"])
                    for root, subdirs, files in os.walk('/opt/havoc/shared'):
                        for filename in files:
                            corrected_root = re.match('/opt/havoc/shared/(.*)', root).group(1)
                            relative_path = os.path.join(corrected_root, filename)
                            file_list.append(relative_path)
                else:
                    file_list = sync_workspace_http(rt, 'sync_from_workspace')
                if instruct_command == 'Initialize':
                    response_kv = ['status', 'ready']
                else:
                    response_kv = ['outcome', 'success']
                build_output = build_response({response_kv[0]: response_kv[1], 'local_directory_contents': file_list},
                                              'True', user_id, task_name, task_context, task_type, interactive,
                                              instruct_user, instruct_instance, instruct_command, instruct_args,
                                              attack_ip, connection_id, end_time)
                if rt.check:
                    post_response_http(rt, build_output)
                else:
                    print(build_output)
            elif instruct_command == 'sync_to_workspace':
                if not rt.check:
                    file_list = []
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "s3", "sync",
                                     "/opt/havoc/shared/", f"s3://{campaign_id}-workspace/shared"])
                    for root, subdirs, files in os.walk('/opt/havoc/shared'):
                        for filename in files:
                            corrected_root = re.match('/opt/havoc/shared/(.*)', root).group(1)
                            relative_path = os.path.join(corrected_root, filename)
                            file_list.append(relative_path)
                else:
                    file_list = sync_workspace_http(rt, 'sync_to_workspace')
                build_output = build_response({'outcome': 'success', 'local_directory_contents': file_list}, 'False',
                                              user_id, task_name, task_context, task_type, interactive, instruct_user,
                                              instruct_instance, instruct_command, instruct_args, attack_ip,
                                              connection_id, end_time)
                if rt.check:
                    post_response_http(rt, build_output)
                else:
                    print(build_output)
            elif instruct_command == 'terminate' or shutdown:
                build_output = build_response({'status': 'terminating'}, 'True', user_id, task_name,
                                              task_context, task_type, interactive, instruct_user,
                                              instruct_instance, instruct_command, instruct_args, attack_ip,
                                              connection_id, end_time)
                if rt.check:
                    post_response_http(rt, build_output)
                else:
                    print(build_output)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if instruct_instance not in metasploit:
                    metasploit[instruct_instance] = havoc_metasploit.call_msf()
                if instruct_instance in metasploit:
                    metasploit_functions = {
                        'list_exploits': metasploit[instruct_instance].list_exploits,
                        'list_payloads': metasploit[instruct_instance].list_payloads,
                        'list_jobs': metasploit[instruct_instance].list_jobs,
                        'list_sessions': metasploit[instruct_instance].list_sessions,
                        'set_exploit_module': metasploit[instruct_instance].set_exploit_module,
                        'set_exploit_options': metasploit[instruct_instance].set_exploit_options,
                        'set_exploit_target': metasploit[instruct_instance].set_exploit_target,
                        'set_payload_module': metasploit[instruct_instance].set_payload_module,
                        'set_payload_options': metasploit[instruct_instance].set_payload_options,
                        'show_exploit': metasploit[instruct_instance].show_exploit,
                        'show_exploit_options': metasploit[instruct_instance].show_exploit_options,
                        'show_exploit_option_info': metasploit[instruct_instance].show_exploit_option_info,
                        'show_exploit_targets': metasploit[instruct_instance].show_exploit_targets,
                        'show_exploit_evasion': metasploit[instruct_instance].show_exploit_evasion,
                        'show_exploit_payloads': metasploit[instruct_instance].show_exploit_payloads,
                        'show_configured_exploit_options': metasploit[instruct_instance].show_configured_exploit_options,
                        'show_exploit_requirements': metasploit[instruct_instance].show_exploit_requirements,
                        'show_missing_exploit_requirements': metasploit[instruct_instance].show_missing_exploit_requirements,
                        'show_last_exploit_results': metasploit[instruct_instance].show_last_exploit_results,
                        'show_payload': metasploit[instruct_instance].show_payload,
                        'show_payload_options': metasploit[instruct_instance].show_payload_options,
                        'show_payload_option_info': metasploit[instruct_instance].show_payload_option_info,
                        'show_configured_payload_options': metasploit[instruct_instance].show_configured_payload_options,
                        'show_payload_requirements': metasploit[instruct_instance].show_payload_requirements,
                        'show_missing_payload_requirements': metasploit[instruct_instance].show_missing_payload_requirements,
                        'show_job_info': metasploit[instruct_instance].show_job_info,
                        'show_session_info': metasploit[instruct_instance].show_session_info,
                        'execute_exploit': metasploit[instruct_instance].execute_exploit,
                        'generate_payload': metasploit[instruct_instance].generate_payload,
                        'run_session_command': metasploit[instruct_instance].run_session_command,
                        'run_session_shell_command': metasploit[instruct_instance].run_session_shell_command,
                        'session_tabs': metasploit[instruct_instance].session_tabs,
                        'load_session_plugin': metasploit[instruct_instance].load_session_plugin,
                        'session_import_psh': metasploit[instruct_instance].session_import_psh,
                        'session_run_psh_cmd': metasploit[instruct_instance].session_run_psh_cmd,
                        'run_session_script': metasploit[instruct_instance].run_session_script,
                        'get_session_writeable_dir': metasploit[instruct_instance].get_session_writeable_dir,
                        'session_read': metasploit[instruct_instance].session_read,
                        'detach_session': metasploit[instruct_instance].detach_session,
                        'kill_session': metasploit[instruct_instance].kill_session,
                        'kill_job': metasploit[instruct_instance].kill_job,
                        'echo': metasploit[instruct_instance].echo
                    }
                    if instruct_command in metasploit_functions:
                        metasploit[instruct_instance].set_args(instruct_args, attack_ip, hostname, local_ip)
                        call_function = metasploit_functions[instruct_command]()
                    else:
                        call_function = {
                            'outcome': 'failed',
                            'message': f'Invalid instruct_command: {instruct_command}',
                            'forward_log': 'False'
                        }

                forward_log = call_function['forward_log']
                del call_function['forward_log']
                build_output = build_response(call_function, forward_log, user_id, task_name, task_type,
                                              task_context, interactive, instruct_user, instruct_instance,
                                              instruct_command, instruct_args, attack_ip, connection_id, end_time)
                if rt.check:
                    post_response_http(rt, build_output)
                else:
                    print(build_output)
            command_list.remove(c)
        yield sleep(1)


@inlineCallbacks
def get_command_obj(region, campaign_id, task_name, rt, command_list):
    if not rt.check:
        client = boto3.client('s3', region_name=region)
    else:
        client = None
    while True:
        yield sleep(12)
        if rt.check:
            get_commands_http(rt, task_name, command_list)
        else:
            get_commands_s3(client, campaign_id, task_name, command_list)


def main():
    log.startLogging(sys.stdout)
    task_type = 'metasploit'
    region = None
    end_time = None
    api_key = None
    secret_key = None
    remote_api_endpoint = None
    manage_api_endpoint = None

    campaign_id = os.environ['CAMPAIGN_ID']
    user_id = os.environ['USER_ID']
    task_name = os.environ['TASK_NAME']
    task_context = os.environ['TASK_CONTEXT']
    if 'REMOTE_TASK' in os.environ:
        if not os.environ.keys() >= {'API_KEY', 'SECRET_KEY', 'REMOTE_API_ENDPOINT', 'MANAGE_API_ENDPOINT'}:
            print('Error: API_KEY, SECRET_KEY, REMOTE_API_ENDPOINT and MANAGE_API_ENDPOINT environment variables must '
                  'be set to run a remote task')
            subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
        else:
            api_key = os.environ['API_KEY']
            secret_key = os.environ['SECRET_KEY']
            remote_api_endpoint = os.environ['REMOTE_API_ENDPOINT']
            manage_api_endpoint = os.environ['MANAGE_API_ENDPOINT']
    else:
        region = os.environ['REGION']
    if 'END_TIME' in os.environ:
        end_time = os.environ['END_TIME']

    # Instantiate Remote to serve key_pair as a property if task is a remote task
    rt = Remote(api_key, secret_key, remote_api_endpoint, manage_api_endpoint)

    # Get public IP
    r = requests.get('http://checkip.amazonaws.com/')
    attack_ip = r.text.rstrip()
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)


    # Setup coroutine resources
    command_list = []

    # Setup coroutines
    get_command_obj(region, campaign_id, task_name, rt, command_list)
    action(campaign_id, user_id, task_type, task_name, task_context, rt, end_time, command_list, attack_ip, hostname,
           local_ip)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()