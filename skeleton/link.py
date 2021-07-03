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
import havoc

# Havoc imports - name your custom module havoc_object or change the import below to reflect the name of your module
import havoc_object


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
            command_list.append(interaction)
            delete_object_response = client.delete_object(
                Bucket=f'{campaign_id}-workspace',
                Key=file_entry
            )
            assert delete_object_response, f"delete_object failed for task {task_name}, key {file_entry}"


def get_commands_http(rt, task_name, command_list):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    commands_response = h.get_commands(task_name)
    if not commands_response:
        print(f"get_commands_http failed for task {task_name}")
        subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)

    if 'commands' in commands_response:
        for command in commands_response['commands']:
            command_list.append(command)


def post_response_http(rt, results):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    post_response = h.post_response(results)
    if not post_response:
        print(f"post_response_http failed for results {results}")
        subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)


def sync_workspace_http(rt, sync_direction):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    sync_workspace_response = h.sync_workspace(sync_direction, '/opt/havoc/shared')
    return sync_workspace_response


def send_response(rt, task_response, forward_log, user_id, task_name, task_context, task_type, instruct_user_id,
                   instruct_instance, instruct_command, instruct_args, attack_ip, local_ip, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    if not rt.check:
        local_ip = 'None'
    output = {
        'task_response': task_response, 'user_id': user_id, 'task_name': task_name, 'task_context': task_context,
        'task_type': task_type, 'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance,
        'instruct_command': instruct_command, 'instruct_args': instruct_args, 'attack_ip': attack_ip,
        'local_ip': local_ip, 'end_time': end_time, 'forward_log': forward_log, 'timestamp': stime
    }
    if rt.check:
        post_response_http(rt, output)
    else:
        print(output)


@inlineCallbacks
def action(campaign_id, user_id, task_type, task_name, task_context, rt, end_time, command_list, attack_ip, hostname,
           local_ip):
    call_function = None
    local_instruct_instance = {}

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
                send_response(rt, {response_kv[0]: response_kv[1], 'local_directory_contents': file_list}, 'True',
                              user_id, task_name, task_context, task_type, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, attack_ip, local_ip, end_time)
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
                send_response(rt, {'outcome': 'success', 'local_directory_contents': file_list}, 'False', user_id,
                              task_name, task_context, task_type, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'terminate' or shutdown:
                send_response(rt, {'status': 'terminating'}, 'True', user_id, task_name, task_context, task_type,
                              instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip, local_ip,
                              end_time)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if instruct_instance not in local_instruct_instance:
                    local_instruct_instance[instruct_instance] = havoc_object.call_object()
                if instruct_instance in local_instruct_instance:
                    object_functions = {
                        'echo': local_instruct_instance[instruct_instance].echo
                    }
                    if instruct_command in object_functions:
                        local_instruct_instance[instruct_instance].set_args(instruct_args, attack_ip, hostname,
                                                                            local_ip)
                        call_function = object_functions[instruct_command]()
                    else:
                        call_function = {
                            'outcome': 'failed',
                            'message': f'Invalid instruct_command: {instruct_command}',
                            'forward_log': 'False'
                        }

                forward_log = call_function['forward_log']
                del call_function['forward_log']
                send_response(rt, call_function, forward_log, user_id, task_name, task_context, task_type,
                              instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip, local_ip,
                              end_time)
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
    task_type = '<custom_task_type>'
    region = None
    api_key = None
    secret = None
    api_domain_name = None
    api_region = None

    # Setup vars
    campaign_id = os.environ['CAMPAIGN_ID']
    user_id = os.environ['USER_ID']
    task_name = os.environ['TASK_NAME']
    task_context = os.environ['TASK_CONTEXT']
    if 'REMOTE_TASK' in os.environ:
        if not os.environ.keys() >= {'API_KEY', 'SECRET', 'API_DOMAIN_NAME', 'API_REGION'}:
            print('Error: API_KEY, SECRET, API_DOMAIN_NAME and API_REGION environment variables must be set to run'
                  ' a remote task')
            subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
        api_key = os.environ['API_KEY']
        secret = os.environ['SECRET']
        api_domain_name = os.environ['API_DOMAIN_NAME']
        api_region = os.environ['API_REGION']
        remote_task_values = {
            'API_KEY': api_key, 'SECRET': secret, 'API_DOMAIN_NAME': api_domain_name, 'API_REGION': api_region
        }
        for k, v in remote_task_values.items():
            if not v:
                print(f'Error: value for {k} cannot be empty')
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
    else:
        region = os.environ['REGION']
    if 'END_TIME' in os.environ:
        end_time = os.environ['END_TIME']
    else:
        end_time = 'None'

    # Instantiate Remote to serve key_pair as a property if task is a remote task
    rt = Remote(api_key, secret, api_domain_name, api_region)

    # Get public IP
    r = requests.get('http://checkip.amazonaws.com/')
    attack_ip = r.text.rstrip()
    hostname = socket.gethostname()
    local_ip = get_ip()

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
    get_command_obj(region, campaign_id, task_name, rt, command_list)
    action(campaign_id, user_id, task_type, task_name, task_context, rt, end_time, command_list, attack_ip, hostname,
           local_ip)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()