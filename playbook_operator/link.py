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

# Havoc imports - name your custom module havoc_module or change the import below to reflect the name of your module
import havoc_module


def sleep(delay):
    d = Deferred()
    reactor.callLater(delay, d.callback, None)
    return d


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



def send_response(task_response, forward_log, user_id, task_name, task_context, task_type, task_version,
                  instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip, local_ip, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    output = {
        'instruct_command_output': task_response, 'user_id': user_id, 'task_name': task_name,
        'task_context': task_context, 'task_type': task_type, 'task_version': task_version,
        'instruct_user_id': instruct_user_id, 'instruct_instance': instruct_instance, 'instruct_command': instruct_command,
        'instruct_args': instruct_args, 'attack_ip': attack_ip, 'local_ip': local_ip, 'end_time': end_time,
        'forward_log': forward_log, 'timestamp': stime
    }
    print(output)


@inlineCallbacks
def action(region, deployment_name, user_id, task_type, task_version, task_commands, task_name, task_context, command_list,
           attack_ip, hostname, local_ip):
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
            end_time = 'None'
            if instruct_command == 'Initialize' or instruct_command == 'sync_from_workspace':
                file_list = []
                subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                    "sync", f"s3://{deployment_name}-workspace/shared", "/opt/havoc/shared/"])
                for root, subdirs, files in os.walk('/opt/havoc/shared'):
                    for filename in files:
                        file_list.append(filename)
                if instruct_command == 'Initialize':
                    response_kv = ['status', 'ready']
                else:
                    response_kv = ['outcome', 'success']
                send_response({response_kv[0]: response_kv[1], 'local_directory_contents': file_list}, 'True', user_id,
                              task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'ls':
                file_list = []
                for root, subdirs, files in os.walk('/opt/havoc/shared'):
                    for filename in files:
                        file_list.append(filename)
                send_response({'outcome': 'success', 'local_directory_contents': file_list}, 'False', user_id, 
                              task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'del':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    path = pathlib.Path(f'/opt/havoc/shared/{file_name}')
                    if path.is_file():
                        os.remove(path)
                        send_response({'outcome': 'success'}, 'True', user_id, task_name, task_context, task_type,
                                      task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args,
                                      attack_ip, local_ip, end_time)
                    else:
                        send_response({'outcome': 'failed', 'message': 'File not found'}, 'False', user_id, task_name,
                                      task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, attack_ip, local_ip, end_time)
                else:
                    send_response({'outcome': 'failed', 'message': 'Missing file_name'}, 'False', user_id, task_name,
                                  task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                  instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'sync_to_workspace':
                file_list = []
                subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                    "sync", "/opt/havoc/shared/", f"s3://{deployment_name}-workspace/shared"])
                for root, subdirs, files in os.walk('/opt/havoc/shared'):
                    for filename in files:
                        file_list.append(filename)
                send_response({'outcome': 'success', 'local_directory_contents': file_list}, 'False', user_id, task_name,
                              task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'upload_to_workspace':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    path = pathlib.Path(f'/opt/havoc/shared/{file_name}')
                    if path.is_file():
                        subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type",
                                            "s3", "cp", f"/opt/havoc/shared/{file_name}",
                                            f"s3://{deployment_name}-workspace/shared/{file_name}"])
                        send_response({'outcome': 'success'}, 'True', user_id, task_name, task_context, task_type,
                                      task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args,
                                      attack_ip, local_ip, end_time)
                    else:
                        send_response({'outcome': 'failed', 'message': 'File not found'}, 'False', user_id, task_name,
                                      task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, attack_ip, local_ip, end_time)
                else:
                    send_response({'outcome': 'failed', 'message': 'Missing file_name'}, 'False',
                                  user_id, task_name, task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                  instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'download_from_workspace':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    file_not_found = False
                    s = subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type",
                                        "s3", "cp", f"s3://{deployment_name}-workspace/shared/{file_name}",
                                        f"/opt/havoc/shared/{file_name}"])
                    if s == 1:
                        file_not_found = True
                    if file_not_found:
                        send_response({'outcome': 'failed', 'message': 'File not found'}, 'False', user_id, task_name,
                                      task_context, task_type, task_version, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, attack_ip, local_ip, end_time)
                    else:
                        send_response({'outcome': 'success'}, 'True', user_id, task_name, task_context, task_type,
                                      task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args,
                                      attack_ip, local_ip, end_time)
                else:
                    send_response({'outcome': 'failed', 'message': 'Missing file_name'}, 'False', user_id, task_name,
                                  task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                                  instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'terminate':
                send_response({'outcome': 'success', 'status': 'terminating'}, 'True', user_id, task_name,
                              task_context, task_type, task_version, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, attack_ip, local_ip, end_time)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if instruct_instance not in local_instruct_instance:
                    local_instruct_instance[instruct_instance] = havoc_module.call_object()
                if instruct_command in task_commands:
                    local_instruct_instance[instruct_instance].set_args(region, deployment_name, instruct_args, attack_ip, hostname,
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
                send_response(call_method, forward_log, user_id, task_name, task_context, task_type,
                              task_version, instruct_user_id, instruct_instance, instruct_command, instruct_args,
                              attack_ip, local_ip, end_time)
            command_list.remove(c)
        yield sleep(1)


@inlineCallbacks
def get_command_obj(region, deployment_name, task_name, command_list):
    client = boto3.client('s3', region_name=region)
    while True:
        yield sleep(6)
        get_commands_s3(client, deployment_name, task_name, command_list)


def main():

    config = ConfigParser()
    config.read('link.ini')
    task_type = config.get('task', 'task_type')
    task_version = config.get('task', 'task_version')
    task_commands = config.get('task', 'task_commands').split(',')

    log.startLogging(sys.stdout)

    # Setup vars
    deployment_name = os.environ['DEPLOYMENT_NAME']
    user_id = os.environ['USER_ID']
    task_name = os.environ['TASK_NAME']
    task_context = os.environ['TASK_CONTEXT']
    region = os.environ['REGION']
    local_ip = [get_ip()]

    # Get public IP
    try:
        r = requests.get('http://checkip.amazonaws.com/', timeout=10)
        attack_ip = r.text.rstrip()
    except requests.ConnectionError:
        print('Public IP check failed. Exiting...')
        subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
    hostname = socket.gethostname()

    # Setup coroutine resources
    command_list = []

    # Setup coroutines
    get_command_obj(region, deployment_name, task_name, command_list)
    action(region, deployment_name, user_id, task_type, task_version, task_commands, task_name, task_context, command_list, attack_ip,
           hostname, local_ip)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()