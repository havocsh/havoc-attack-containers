#!/usr/bin/python3

import os
import re
import sys
import json
import boto3
import socket
import requests
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, Deferred
import havoc

# Havoc imports
import havoc_powershell_empire


class Remote:
    def __init__(self, api_key, secret, api_domain_name, api_region):
        self.api_key = api_key
        self.secret = secret
        self.api_domain_name = api_domain_name
        self.api_region = api_region
        self.__check = None

    @property
    def check(self):
        if self.api_key and self.secret and self.api_domain_name and self.api_region:
            self.__check = True
        return self.__check


def sleep(delay):
    d = Deferred()
    reactor.callLater(delay, d.callback, None)
    return d


def shutdown_timer(end_time):
    timestamp = datetime.strptime(end_time, "%m/%d/%Y %H:%M:%S %z")
    if datetime.now(timezone.utc) >= timestamp:
        return True


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def get_commands_s3(client, campaign_id, task_name, command_list, user_id):
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
            command_list.append(interaction)
            delete_object_response = client.delete_object(
                Bucket=f'{campaign_id}-workspace',
                Key=file_entry
            )
            assert delete_object_response, f"delete_object failed for task {task_name}, key {file_entry}"
    else:
        command_list.append(
            {
                'instruct_user_id': user_id,
                'instruct_instance': 'agent_status_monitor',
                'instruct_command': 'agent_status_monitor',
                'instruct_args': None
            }
        )


def get_commands_http(rt, task_name, command_list, user_id):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    commands_response = h.get_commands(task_name)
    if not commands_response:
        print(f"get_commands_http failed for task {task_name}")

    if 'commands' in commands_response:
        for command in commands_response['commands']:
            command_list.append(command)
    else:
        command_list.append(
            {
                'instruct_user_id': user_id,
                'instruct_instance': 'agent_status_monitor',
                'instruct_command': 'agent_status_monitor',
                'instruct_args': None
            }
        )


def post_response_http(rt, results):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    post_response = h.post_response(results)
    if not post_response:
        print(f"post_response_http failed for results {results}")


def sync_workspace_http(rt, sync_direction):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    sync_workspace_response = h.sync_workspace(sync_direction, '/opt/havoc/shared')
    return sync_workspace_response


def file_transfer_http(rt, sync_direction, file_name):
    success = False
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    if sync_direction == 'download_from_workspace':
        file_transfer_response = h.get_file(file_name)
        if file_transfer_response:
            with open(f'/opt/havoc/share/{file_name}', 'wb') as w:
                w.write(file_transfer_response['file_contents'])
            success = True
    if sync_direction == 'upload_to_workspace':
        with open (f'opt/havoc/shared/{file_name}', 'rb') as raw_file:
            h.create_file(file_name, raw_file.read())
        success = True
    return success


def send_response(rt, task_response, forward_log, user_id, task_name, task_context, task_type, instruct_user_id,
                   instruct_instance, instruct_command, instruct_args, attack_ip, local_ip, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    output = {
        'instruct_command_output': task_response, 'user_id': user_id, 'task_name': task_name,
        'task_context': task_context, 'task_type': task_type, 'instruct_user_id': instruct_user_id,
        'instruct_instance': instruct_instance, 'instruct_command': instruct_command, 'instruct_args': instruct_args,
        'attack_ip': attack_ip, 'local_ip': local_ip, 'end_time': end_time, 'forward_log': forward_log,
        'timestamp': stime
    }
    if rt.check:
        post_response_http(rt, output)
    else:
        print(output)


@inlineCallbacks
def action(campaign_id, user_id, task_type, task_name, task_context, rt, end_time, command_list, attack_ip, hostname,
           local_ip):
    powershell_empire = {}
    current_agents = []

    while True:
        def sortFunc(e):
            return e['timestamp']

        command_list.sort(key=sortFunc)
        for c in command_list:
            instruct_user_id = c['instruct_user_id']
            instruct_instance = c['instruct_instance']
            instruct_command = c['instruct_command']
            instruct_args = c['instruct_args']
            shutdown = None
            if end_time != 'None':
                shutdown = shutdown_timer(end_time)
            if c['end_time'] != 'None':
                end_time = c['end_time']
                shutdown = shutdown_timer(end_time)
            if instruct_command == 'Initialize' or instruct_command == 'sync_from_workspace':
                if not rt.check:
                    file_list = []
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                     "sync", f"s3://{campaign_id}-workspace/shared", "/opt/havoc/shared/"])
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
                send_response(rt, {response_kv[0]: response_kv[1], 'local_directory_contents': file_list}, 'True',
                              user_id, task_name, task_context, task_type, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'sync_to_workspace':
                if not rt.check:
                    file_list = []
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                     "sync", "/opt/havoc/shared/", f"s3://{campaign_id}-workspace/shared"])
                    for root, subdirs, files in os.walk('/opt/havoc/shared'):
                        for filename in files:
                            corrected_root = re.match('/opt/havoc/shared/(.*)', root).group(1)
                            relative_path = os.path.join(corrected_root, filename)
                            file_list.append(relative_path)
                else:
                    file_list = sync_workspace_http(rt, 'sync_to_workspace')
                send_response(rt, {'outcome': 'success', 'local_directory_contents': file_list}, 'False', user_id,
                              task_name, task_context, task_type, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'upload_to_workspace':
                if 'filename' in instruct_args:
                    file_name = instruct_args['filename']
                    if file_name.is_file():
                        if not rt.check:
                            subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type",
                                             "s3", "cp", f"/opt/havoc/shared/{file_name}",
                                             f"s3://{campaign_id}-workspace/shared/{file_name}"])
                        else:
                            file_transfer_http(rt, 'upload_to_workspace', file_name)
                        send_response(rt, {'outcome': 'success'}, 'True', user_id, task_name, task_context, task_type,
                                      instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip,
                                      local_ip, end_time)
                    else:
                        send_response(rt, {'outcome': 'failed', 'message': 'File not found'}, 'False', user_id,
                                      task_name, task_context, task_type, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, attack_ip, local_ip, end_time)
                else:
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing filename'}, 'False',
                                  user_id, task_name, task_context, task_type, instruct_user_id, instruct_instance,
                                  instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'download_from_workspace':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    file_not_found = False
                    if not rt.check:
                        s = subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type",
                                         "s3", "cp", f"s3://{campaign_id}-workspace/shared/{file_name}",
                                         f"/opt/havoc/shared/{file_name}"])
                        if s == 1:
                            file_not_found = True
                    else:
                        file_download = file_transfer_http(rt,'download_from_workspace', file_name)
                        if not file_download:
                            file_not_found = True
                    if file_not_found:
                        send_response(rt, {'outcome': 'failed', 'message': 'File not found'}, 'False', user_id,
                                      task_name, task_context, task_type, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, attack_ip, local_ip, end_time)
                    else:
                        send_response(rt, {'outcome': 'success'}, 'True', user_id, task_name, task_context, task_type,
                                      instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip,
                                      local_ip, end_time)
                else:
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing filename'}, 'False', user_id, task_name,
                                  task_context, task_type, instruct_user_id, instruct_instance, instruct_command,
                                  instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'agent_status_monitor':
                powershell_empire[instruct_instance] = havoc_powershell_empire.call_powershell_empire()
                instruct_args = {'current_agents': current_agents}
                powershell_empire[instruct_instance].set_args(instruct_args, attack_ip, hostname, local_ip)
                call_agent_status_monitor = powershell_empire[instruct_instance].agent_status_monitor()
                new_agents = call_agent_status_monitor['new_agents']
                dead_agents = call_agent_status_monitor['dead_agents']
                for new_agent in new_agents:
                    current_agents.append(new_agent)
                    p = havoc_powershell_empire.PowershellEmpireParser(new_agent, True)
                    new_agent_parsed = p.powershell_empire_parser()
                    new_agent_response = {'outcome': 'success', 'agent_connected': 'True'}
                    for k, v in new_agent_parsed.items():
                        new_agent_response[k] = v
                    send_response(rt, new_agent_response, 'True', user_id, task_name, task_context, task_type,
                                  instruct_user_id, instruct_instance, instruct_command, {'no_args': 'True'}, attack_ip,
                                  local_ip, end_time)
                for dead_agent in dead_agents:
                    p = havoc_powershell_empire.PowershellEmpireParser(dead_agent, True)
                    dead_agent_parsed = p.powershell_empire_parser()
                    dead_agent_response = {'outcome': 'success', 'agent_killed': 'True'}
                    for k, v in dead_agent_parsed.items():
                        dead_agent_response[k] = v
                    send_response(rt, dead_agent_response, 'True', user_id, task_name, task_context, task_type,
                                  instruct_user_id, instruct_instance, instruct_command, {'no_args': 'True'}, attack_ip,
                                  local_ip, end_time)
                    current_agents=[x for x in current_agents if x['ID'] not in dead_agent['ID']]
            elif instruct_command == 'terminate' or shutdown:
                send_response(rt, {'status': 'terminating'}, 'True', user_id, task_name, task_context, task_type,
                              instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip, local_ip,
                              end_time)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if instruct_instance not in powershell_empire:
                    powershell_empire[instruct_instance] = havoc_powershell_empire.call_powershell_empire()
                powershell_empire_functions = {
                    'get_listeners': powershell_empire[instruct_instance].get_listeners,
                    'get_listener_options': powershell_empire[instruct_instance].get_listener_options,
                    'create_listener': powershell_empire[instruct_instance].create_listener,
                    'kill_listener': powershell_empire[instruct_instance].kill_listener,
                    'kill_all_listeners': powershell_empire[instruct_instance].kill_all_listeners,
                    'get_stagers': powershell_empire[instruct_instance].get_stagers,
                    'create_stager': powershell_empire[instruct_instance].create_stager,
                    'get_agents': powershell_empire[instruct_instance].get_agents,
                    'get_stale_agents': powershell_empire[instruct_instance].get_stale_agents,
                    'remove_agent': powershell_empire[instruct_instance].remove_agent,
                    'remove_stale_agents': powershell_empire[instruct_instance].remove_stale_agents,
                    'agent_shell_command': powershell_empire[instruct_instance].agent_shell_command,
                    'clear_queued_shell_commands': powershell_empire[instruct_instance].clear_queued_shell_commands,
                    'rename_agent': powershell_empire[instruct_instance].rename_agent,
                    'kill_agent': powershell_empire[instruct_instance].kill_agent,
                    'kill_all_agents': powershell_empire[instruct_instance].kill_all_agents,
                    'get_modules': powershell_empire[instruct_instance].get_modules,
                    'search_modules': powershell_empire[instruct_instance].search_modules,
                    'execute_module': powershell_empire[instruct_instance].execute_module,
                    'get_stored_credentials': powershell_empire[instruct_instance].get_stored_credentials,
                    'get_logged_events': powershell_empire[instruct_instance].get_logged_events,
                    'cert_gen': powershell_empire[instruct_instance].cert_gen,
                    'echo': powershell_empire[instruct_instance].echo
                }
                if instruct_command in powershell_empire_functions:
                    powershell_empire[instruct_instance].set_args(instruct_args, attack_ip, hostname, local_ip)
                    call_function = powershell_empire_functions[instruct_command]()
                else:
                    call_function = {
                        'outcome': 'failed',
                        'message': f'Invalid instruct_command: {instruct_command}',
                        'forward_log': 'False'
                    }

                forward_log = call_function['forward_log']
                del call_function['forward_log']
                p = havoc_powershell_empire.PowershellEmpireParser(call_function)
                task_response = p.powershell_empire_parser()
                send_response(rt, task_response, forward_log, user_id, task_name, task_context, task_type,
                              instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip, local_ip,
                              end_time)
            command_list.remove(c)
        yield sleep(1)


@inlineCallbacks
def get_command_obj(region, campaign_id, task_name, rt, command_list, user_id):
    if not rt.check:
        client = boto3.client('s3', region_name=region)
    else:
        client = None
    while True:
        yield sleep(6)
        if rt.check:
            get_commands_http(rt, task_name, command_list, user_id)
        else:
            get_commands_s3(client, campaign_id, task_name, command_list, user_id)


def main():
    log.startLogging(sys.stdout)
    task_type = '<custom_task_type>'
    region = None
    api_key = None
    secret = None
    api_domain_name = None
    api_region = None
    attack_ip = None

    # Setup vars
    campaign_id = os.environ['CAMPAIGN_ID']
    user_id = os.environ['USER_ID']
    task_name = os.environ['TASK_NAME']
    task_context = os.environ['TASK_CONTEXT']
    if 'REMOTE_TASK' in os.environ:
        if not os.environ.keys() >= {'API_KEY', 'SECRET', 'API_DOMAIN_NAME', 'API_REGION', 'LOCAL_IP'}:
            print('Error: API_KEY, SECRET, API_DOMAIN_NAME and API_REGION environment variables must be set to run'
                  ' a remote task')
            subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
        api_key = os.environ['API_KEY']
        secret = os.environ['SECRET']
        api_domain_name = os.environ['API_DOMAIN_NAME']
        api_region = os.environ['API_REGION']
        local_ip = os.environ['LOCAL_IP'].split()
        remote_task_values = {
            'API_KEY': api_key,
            'SECRET': secret,
            'API_DOMAIN_NAME': api_domain_name,
            'API_REGION': api_region,
            'LOCAL_IP': local_ip
        }
        for k, v in remote_task_values.items():
            if not v:
                print(f'Error: value for {k} cannot be empty')
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
    else:
        region = os.environ['REGION']
        local_ip = ['None']
    if 'END_TIME' in os.environ:
        end_time = os.environ['END_TIME']
    else:
        end_time = 'None'

    # Instantiate Remote to serve key_pair as a property if task is a remote task
    rt = Remote(api_key, secret, api_domain_name, api_region)

    # Get public IP
    try:
        r = requests.get('http://checkip.amazonaws.com/', timeout=10)
        attack_ip = r.text.rstrip()
    except requests.ConnectionError:
        print('Public IP check failed. Exiting...')
        subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
    hostname = socket.gethostname()

    # If this is a remote task, register it as such
    if rt.check:
        h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
        task_registration = h.register_task(task_name, task_context, task_type, attack_ip, local_ip)
        if not task_registration:
            print('Remote task registration failed. Exiting...')
            subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)

    # Setup coroutine resources
    command_list = []

    # Setup coroutines
    get_command_obj(region, campaign_id, task_name, rt, command_list, user_id)
    action(campaign_id, user_id, task_type, task_name, task_context, rt, end_time, command_list, attack_ip, hostname,
           local_ip)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()