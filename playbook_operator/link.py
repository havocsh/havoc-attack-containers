#!/usr/bin/python3

import os
import re
import sys
import json
import boto3
import subprocess
import time as t
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


def get_commands_s3(client, deployment_name, playbook_name, command_list):
    list_objects_response = None
    try:
        list_objects_response = client.list_objects_v2(
            Bucket=f'{deployment_name}-playbooks',
            Prefix=playbook_name + '/'
        )
    except Exception as err:
        print(f'get_commands_s3 function failed. Error: {err}')
    file_list = []
    regex = f'{playbook_name}/(.*)'
    if list_objects_response and 'Contents' in list_objects_response:
        for file_object in list_objects_response['Contents']:
            search = re.search(regex, file_object['Key'])
            if search.group(1):
                file_list.append(file_object['Key'])
        for file_entry in file_list:
            get_object_response = None
            try:
                get_object_response = client.get_object(
                    Bucket=f'{deployment_name}-playbooks',
                    Key=file_entry
                )
            except Exception as err:
                print(f'get_object failed for playbook_name {playbook_name}, key {file_entry} with error {err}')
            if get_object_response and 'Body' in get_object_response:
                interaction = json.loads(get_object_response['Body'].read().decode('utf-8'))
                command_list.append(interaction)
                try:
                    client.delete_object(
                        Bucket=f'{deployment_name}-playbooks',
                        Key=file_entry
                    )
                except Exception as err:
                    print(f'delete_object failed for playbook_name {playbook_name}, key {file_entry} with error {err}')



def send_response(playbook_operator_response, forward_log, user_id, playbook_name, playbook_operator_version,
                  operator_command, command_args, end_time):
    stime = datetime.now(timezone.utc).strftime('%s')
    output = {
        'command_output': playbook_operator_response, 'user_id': user_id, 'playbook_operator_version': playbook_operator_version, 
        'playbook_name': playbook_name, 'operator_command': operator_command, 'command_args': command_args, 'end_time': end_time,
        'forward_log': forward_log, 'timestamp': stime
    }
    print(output)


@inlineCallbacks
def action(region, deployment_name, user_id, playbook_operator_version, commands, playbook_name, command_list, end_time):
    playbook_execution = havoc_module.call_object()

    while True:
        def sortFunc(e):
            return e['timestamp']

        command_list.sort(key=sortFunc)
        for c in command_list:
            operator_command = c['operator_command']
            command_args = c['command_args']
            end_time = c['end_time']
            if operator_command == 'Initialize':
                send_response({'status': 'ready'}, 'True', user_id, playbook_name, playbook_operator_version, operator_command,
                              command_args, end_time)
            elif operator_command == 'terminate':
                send_response({'outcome': 'success', 'status': 'terminating'}, 'True', user_id, playbook_name, 
                              playbook_operator_version, operator_command, command_args, end_time)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if operator_command in commands:
                    playbook_execution.set_args(region, deployment_name, user_id, playbook_name, playbook_operator_version, command_args, end_time)
                    method = getattr(playbook_execution, operator_command)
                    call_method = method()
                else:
                    call_method = {
                        'outcome': 'failed',
                        'message': f'Invalid operator_command: {operator_command}',
                        'forward_log': 'False'
                    }

                forward_log = call_method['forward_log']
                del call_method['forward_log']
                for k in command_args.keys():
                    if k == 'secret':
                        command_args[k] = '************************'
                send_response(call_method, forward_log, user_id, playbook_name, playbook_operator_version, operator_command,
                              command_args, end_time)
                if call_method:
                    t.sleep(5)
                    timestamp = datetime.now().strftime('%s')
                    terminate_command = {'operator_command': 'terminate', 'command_args': {'no_args': 'True'}, 'timestamp': timestamp, 'end_time': end_time}
                    command_list.append(terminate_command)
            command_list.remove(c)
        yield sleep(1)


@inlineCallbacks
def get_command_obj(region, deployment_name, playbook_name, command_list):
    client = boto3.client('s3', region_name=region)
    while True:
        yield sleep(6)
        get_commands_s3(client, deployment_name, playbook_name, command_list)


def main():

    config = ConfigParser()
    config.read('link.ini')
    playbook_operator_version = config.get('playbook_operator', 'version')
    commands = config.get('playbook_operator', 'commands').split(',')

    log.startLogging(sys.stdout)

    # Setup vars
    deployment_name = os.environ['DEPLOYMENT_NAME']
    user_id = os.environ['USER_ID']
    playbook_name = os.environ['PLAYBOOK_NAME']
    region = os.environ['REGION']
    end_time = os.environ['END_TIME']

    # Setup coroutine resources
    command_list = []

    # Setup coroutines
    get_command_obj(region, deployment_name, playbook_name, command_list)
    action(region, deployment_name, user_id, playbook_operator_version, commands, playbook_name, command_list, end_time)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()