#!/usr/bin/python3

import os
import re
import sys
import json
import boto3
import socket
import pathlib
import requests
import subprocess
from configparser import ConfigParser
from datetime import datetime, timezone
from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, Deferred
import havoc

# Havoc imports - name your custom module havoc_module or change the import below to reflect the name of your module
import havoc_module


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


def get_commands_s3(client, deployment_name, task_name, command_list):
    list_objects_response = None
    try:
        list_objects_response = client.list_objects_v2(
            Bucket=f'{deployment_name}-workspace',
            Prefix=task_name + '/'
        )
    except Exception as err:
        print(f'get_commands_s3 function failed. Error: {err}')
    file_list = []
    regex = f'{task_name}/(.*)'
    if list_objects_response and 'Contents' in list_objects_response:
        for file_object in list_objects_response['Contents']:
            search = re.search(regex, file_object['Key'])
            if search.group(1):
                file_list.append(file_object['Key'])
        for file_entry in file_list:
            get_object_response = None
            try:
                get_object_response = client.get_object(
                    Bucket=f'{deployment_name}-workspace',
                    Key=file_entry
                )
            except Exception as err:
                print(f'get_object failed for task_name {task_name}, key {file_entry} with error {err}')
            if get_object_response and 'Body' in get_object_response:
                interaction = json.loads(get_object_response['Body'].read().decode('utf-8'))
                command_list.append(interaction)
                try:
                    client.delete_object(
                        Bucket=f'{deployment_name}-workspace',
                        Key=file_entry
                    )
                except Exception as err:
                    print(f'delete_object failed for task {task_name}, key {file_entry} with error {err}')


def get_commands_http(rt, task_name, command_list):
    commands_response = None
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    try:
        commands_response = h.get_commands(task_name)
    except Exception as err:
        print(f'get_commands_http failed for task {task_name} with error {err}')

    if commands_response and 'commands' in commands_response:
        for command in commands_response['commands']:
            command_list.append(command)


def post_response_http(rt, results):
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    try:
        h.post_response(results)
    except Exception as err:
        print(f'post_response_http failed for results {results} with error {err}')


def sync_workspace_http(rt, sync_direction):
    sync_workspace_response = None
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    try:
        sync_workspace_response = h.sync_workspace(sync_direction, '/opt/havoc/shared')
    except Exception as err:
        print(f'sync_workspace_http failed with error {err}')
    return sync_workspace_response


def file_transfer_http(rt, sync_direction, file_name):
    success = False
    file_transfer_response = None
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    if sync_direction == 'download_from_workspace':
        try:
            file_transfer_response = h.get_file(file_name)
        except Exception as err:
            print(f'file_transfer_http failed for direction {sync_direction}, file_name {file_name} with error {err}')
        if file_transfer_response and 'file_contents' in file_transfer_response:
            with open(f'/opt/havoc/shared/{file_name}', 'wb') as w:
                w.write(file_transfer_response['file_contents'])
            success = True
        else:
            success = False
    if sync_direction == 'upload_to_workspace':
        try:
            with open (f'opt/havoc/shared/{file_name}', 'rb') as raw_file:
                h.create_file(file_name, raw_file.read())
            success = True
        except Exception as err:
            print(f'file_transfer_http failed for direction {sync_direction}, file_name {file_name} with error {err}')
            success = False
    return success


def send_response(rt, task_response, forward_log, user_id, task_name, task_context, task_type, task_version,
                  instruct_user_id, instruct_instance, instruct_command, instruct_args, public_ip, local_ip, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    output = {
        'instruct_command_output': task_response, 'user_id': user_id, 'task_name': task_name,
        'task_context': task_context, 'task_type': task_type, 'task_version': task_version,
        'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance, 'instruct_command': instruct_command,
        'instruct_args': instruct_args, 'public_ip': public_ip, 'local_ip': local_ip, 'end_time': end_time,
        'forward_log': forward_log, 'timestamp': stime
    }
    if rt.check:
        post_response_http(rt, output)
    else:
        print(output)


@inlineCallbacks
def action(deployment_name, user_id, task_type, task_version, task_commands, task_name, task_context, rt, end_time, command_list,
           public_ip, hostname, local_ip):
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
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                     "sync", f"s3://{deployment_name}-workspace/shared", "/opt/havoc/shared/"])
                    for root, subdirs, files in os.walk('/opt/havoc/shared'):
                        for filename in files:
                            file_list.append(filename)
                else:
                    file_list = sync_workspace_http(rt, 'sync_from_workspace')
                if instruct_command == 'Initialize':
                    command_response = {'status': 'ready', 'Initialize': {'file_list': file_list}}
                else:
                    command_response = {'outcome': 'success', 'sync_from_workspace': {'file_list': file_list}}
                send_response(rt, command_response, 'True', user_id, task_name, task_context, task_type, task_version,
                              instruct_user_id, instruct_instance, instruct_command, instruct_args, public_ip, local_ip, end_time)
            elif instruct_command == 'ls':
                file_list = []
                for root, subdirs, files in os.walk('/opt/havoc/shared'):
                    for filename in files:
                        file_list.append(filename)
                send_response(rt, {'outcome': 'success', 'ls': {'file_list': file_list}}, 'False', user_id, task_name, task_context, task_type,
                              task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args, public_ip,
                              local_ip, end_time)
            elif instruct_command == 'del':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    path = pathlib.Path(f'/opt/havoc/shared/{file_name}')
                    if path.is_file():
                        os.remove(path)
                        send_response(rt, {'outcome': 'success', 'del': {'file_name': file_name}}, 'True', user_id, task_name, task_context, task_type,
                                      task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args,
                                      public_ip, local_ip, end_time)
                    else:
                        send_response(rt, {'outcome': 'failed', 'message': 'File not found'}, 'False', user_id,
                                      task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, public_ip, local_ip, end_time)
                else:
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing file_name'}, 'False',
                                  user_id, task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                  instruct_command, instruct_args, public_ip, local_ip, end_time)
            elif instruct_command == 'sync_to_workspace':
                if not rt.check:
                    file_list = []
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                     "sync", "/opt/havoc/shared/", f"s3://{deployment_name}-workspace/shared"])
                    for root, subdirs, files in os.walk('/opt/havoc/shared'):
                        for filename in files:
                            file_list.append(filename)
                else:
                    file_list = sync_workspace_http(rt, 'sync_to_workspace')
                send_response(rt, {'outcome': 'success', 'sync_to_workspace': {'file_list': file_list}}, 'False', user_id,
                              task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, public_ip, local_ip, end_time)
            elif instruct_command == 'upload_to_workspace':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    path = pathlib.Path(f'/opt/havoc/shared/{file_name}')
                    if path.is_file():
                        if not rt.check:
                            subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type",
                                             "s3", "cp", f"/opt/havoc/shared/{file_name}",
                                             f"s3://{deployment_name}-workspace/shared/{file_name}"])
                        else:
                            file_transfer_http(rt, 'upload_to_workspace', file_name)
                        send_response(rt, {'outcome': 'success', 'upload_to_workspace': {'file_name': file_name}}, 'True', user_id, task_name, 
                                      task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                                      instruct_args, public_ip, local_ip, end_time)
                    else:
                        send_response(rt, {'outcome': 'failed', 'message': 'File not found'}, 'False', user_id,
                                      task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, public_ip, local_ip, end_time)
                else:
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing file_name'}, 'False',
                                  user_id, task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                  instruct_command, instruct_args, public_ip, local_ip, end_time)
            elif instruct_command == 'download_from_workspace':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    file_not_found = False
                    if not rt.check:
                        s = subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type",
                                         "s3", "cp", f"s3://{deployment_name}-workspace/shared/{file_name}",
                                         f"/opt/havoc/shared/{file_name}"])
                        if s == 1:
                            file_not_found = True
                    else:
                        file_download = file_transfer_http(rt,'download_from_workspace', file_name)
                        if not file_download:
                            file_not_found = True
                    if file_not_found:
                        send_response(rt, {'outcome': 'failed', 'message': 'File not found'}, 'False', user_id,
                                      task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, public_ip, local_ip, end_time)
                    else:
                        send_response(rt, {'outcome': 'success', 'download_from_workspace': {'file_name': file_name}}, 'True', user_id, task_name,
                                      task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                                      instruct_args, public_ip, local_ip, end_time)
                else:
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing file_name'}, 'False', user_id, task_name,
                                  task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                                  instruct_args, public_ip, local_ip, end_time)
            elif instruct_command == 'terminate' or shutdown:
                send_response(rt, {'outcome': 'success', 'status': 'terminating'}, 'True', user_id, task_name,
                              task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, public_ip, local_ip, end_time)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if instruct_instance not in local_instruct_instance:
                    local_instruct_instance[instruct_instance] = havoc_module.call_object()
                if instruct_command in task_commands:
                    local_instruct_instance[instruct_instance].set_args(instruct_args, public_ip, hostname,
                                                                        local_ip)
                    method = getattr(local_instruct_instance[instruct_instance], instruct_command)
                    call_method = method()
                else:
                    call_method = {
                        'outcome': 'failed',
                        'message': f'Invalid instruct_command: {instruct_command}',
                        'forward_log': 'False'
                    }

                forward_log = call_method['forward_log']
                del call_method['forward_log']
                send_response(rt, call_method, forward_log, user_id, task_name, task_context, task_type,
                              task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args,
                              public_ip, local_ip, end_time)
            command_list.remove(c)
        yield sleep(1)


@inlineCallbacks
def get_command_obj(region, deployment_name, task_name, rt, command_list):
    if not rt.check:
        client = boto3.client('s3', region_name=region)
    else:
        client = None
    while True:
        yield sleep(6)
        if rt.check:
            get_commands_http(rt, task_name, command_list)
        else:
            get_commands_s3(client, deployment_name, task_name, command_list)


def main():

    config = ConfigParser()
    config.read('link.ini')
    task_type = config.get('task', 'task_type')
    task_version = config.get('task', 'task_version')
    task_commands = config.get('task', 'task_commands').split(',')

    log.startLogging(sys.stdout)
    region = None
    api_key = None
    secret = None
    api_domain_name = None
    api_region = None
    public_ip = None

    # Setup vars
    deployment_name = os.environ['DEPLOYMENT_NAME']
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
        local_ip = [get_ip()]
    if 'END_TIME' in os.environ:
        end_time = os.environ['END_TIME']
    else:
        end_time = 'None'

    # Instantiate Remote to serve key_pair as a property if task is a remote task
    rt = Remote(api_key, secret, api_domain_name, api_region)

    # Get public IP
    try:
        r = requests.get('http://checkip.amazonaws.com/', timeout=10)
        public_ip = r.text.rstrip()
    except requests.ConnectionError:
        print('Public IP check failed. Exiting...')
        subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
    hostname = socket.gethostname()

    # If this is a remote task, register it as such
    if rt.check:
        try:
            h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
            h.register_task(task_name, task_context, task_type, task_version, public_ip, local_ip)
        except Exception as e:
            print(f'Remote task registration failed with error:\n{e}\nExiting...')
            subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)

    # Setup coroutine resources
    command_list = []

    # Setup coroutines
    get_command_obj(region, deployment_name, task_name, rt, command_list)
    action(deployment_name, user_id, task_type, task_version, task_commands, task_name, task_context, rt, end_time, command_list,
           public_ip, hostname, local_ip)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()