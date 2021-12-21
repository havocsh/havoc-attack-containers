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
from datetime import datetime, timezone
from twisted.python import log
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, Deferred
import havoc

# Havoc Imports
import havoc_metasploit


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
    list_objects_response = None
    try:
        list_objects_response = client.list_objects_v2(
            Bucket=f'{campaign_id}-workspace',
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
                    Bucket=f'{campaign_id}-workspace',
                    Key=file_entry
                )
            except Exception as err:
                print(f'get_object failed for task_name {task_name}, key {file_entry} with error {err}')
            if get_object_response and 'Body' in get_object_response:
                interaction = json.loads(get_object_response['Body'].read().decode('utf-8'))
                command_list.append(interaction)
                try:
                    client.delete_object(
                        Bucket=f'{campaign_id}-workspace',
                        Key=file_entry
                    )
                except Exception as err:
                    print(f'delete_object failed for task {task_name}, key {file_entry} with error {err}')
    else:
        timestamp = datetime.now(timezone.utc).strftime('%s')
        command_list.append(
            {
                'timestamp': timestamp,
                'instruct_user_id': user_id,
                'instruct_instance': 'session_status_monitor',
                'instruct_command': 'session_status_monitor',
                'instruct_args': None,
                'end_time': 'None'
            }
        )


def get_commands_http(rt, task_name, command_list, user_id):
    commands_response = None
    h = havoc.Connect(rt.api_region, rt.api_domain_name, rt.api_key, rt.secret)
    try:
        commands_response = h.get_commands(task_name)
    except Exception as err:
        print(f'get_commands_http failed for task {task_name} with error {err}')

    if commands_response and 'commands' in commands_response:
        for command in commands_response['commands']:
            command_list.append(command)
    else:
        timestamp = datetime.now(timezone.utc).strftime('%s')
        command_list.append(
            {
                'timestamp': timestamp,
                'instruct_user_id': user_id,
                'instruct_instance': 'session_status_monitor',
                'instruct_command': 'session_status_monitor',
                'instruct_args': None,
                'end_time': 'None'
            }
        )


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
            with open(f'/opt/havoc/share/{file_name}', 'wb') as w:
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
    call_function = None
    metasploit = {}
    current_sessions = []

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
                            file_list.append(filename)
                else:
                    file_list = sync_workspace_http(rt, 'sync_from_workspace')
                if instruct_command == 'Initialize':
                    response_kv = ['status', 'ready']
                else:
                    response_kv = ['outcome', 'success']
                send_response(rt, {response_kv[0]: response_kv[1], 'local_directory_contents': file_list},
                              'True', user_id, task_name, task_context, task_type, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'ls':
                file_list = []
                for root, subdirs, files in os.walk('/opt/havoc/shared'):
                    for filename in files:
                        file_list.append(filename)
                send_response(rt, {'outcome': 'success', 'local_directory_contents': file_list}, 'False',
                              user_id, task_name, task_context, task_type, instruct_user_id, instruct_instance,
                              instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'del':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    path = pathlib.Path(f'/opt/havoc/shared/{file_name}')
                    if path.is_file():
                        os.remove(path)
                        send_response(rt, {'outcome': 'success'}, 'True', user_id, task_name, task_context, task_type,
                                      instruct_user_id, instruct_instance, instruct_command, instruct_args, attack_ip,
                                      local_ip, end_time)
                    else:
                        send_response(rt, {'outcome': 'failed', 'message': 'File not found'}, 'False', user_id,
                                      task_name, task_context, task_type, instruct_user_id, instruct_instance,
                                      instruct_command, instruct_args, attack_ip, local_ip, end_time)
                else:
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing file_name'}, 'False',
                                  user_id, task_name, task_context, task_type, instruct_user_id, instruct_instance,
                                  instruct_command, instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'sync_to_workspace':
                if not rt.check:
                    file_list = []
                    subprocess.call(["aws", "--quiet", "--no-paginate", "--no-progress", "--no-guess-mime-type", "s3",
                                     "sync", "/opt/havoc/shared/", f"s3://{campaign_id}-workspace/shared"])
                    for root, subdirs, files in os.walk('/opt/havoc/shared'):
                        for filename in files:
                            file_list.append(filename)
                else:
                    file_list = sync_workspace_http(rt, 'sync_to_workspace')
                send_response(rt, {'outcome': 'success', 'local_directory_contents': file_list}, 'False', user_id,
                              task_name, task_context, task_type, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'upload_to_workspace':
                if 'file_name' in instruct_args:
                    file_name = instruct_args['file_name']
                    path = pathlib.Path(f'/opt/havoc/shared/{file_name}')
                    if path.is_file():
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
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing file_name'}, 'False',
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
                    send_response(rt, {'outcome': 'failed', 'message': 'Missing file_name'}, 'False', user_id, task_name,
                                  task_context, task_type, instruct_user_id, instruct_instance, instruct_command,
                                  instruct_args, attack_ip, local_ip, end_time)
            elif instruct_command == 'session_status_monitor':
                metasploit[instruct_instance] = havoc_metasploit.call_msf(campaign_id)
                instruct_args = {'current_sessions': current_sessions}
                metasploit[instruct_instance].set_args(instruct_args, attack_ip, hostname, local_ip)
                call_session_status_monitor = metasploit[instruct_instance].session_status_monitor()
                new_sessions = call_session_status_monitor['new_sessions']
                dead_sessions = call_session_status_monitor['dead_sessions']
                for new_session in new_sessions:
                    current_sessions.append(new_session)
                    m = havoc_metasploit.MetasploitParser(new_session)
                    new_session_parsed = m.metasploit_parser()
                    new_session_response = {'outcome': 'success', 'session_connected': 'True'}
                    for k, v in new_session_parsed.items():
                        new_session_response[k] = v
                    send_response(rt, new_session_response, 'True', user_id, task_name, task_context, task_type,
                                  instruct_user_id, instruct_instance, instruct_command, {'no_args': 'True'}, attack_ip,
                                  local_ip, end_time)
                for dead_session in dead_sessions:
                    m = havoc_metasploit.MetasploitParser(dead_session)
                    dead_session_parsed = m.metasploit_parser()
                    dead_session_response = {'outcome': 'success', 'session_killed': 'True'}
                    for k, v in dead_session_parsed.items():
                        dead_session_response[k] = v
                    send_response(rt, dead_session_response, 'True', user_id, task_name, task_context, task_type,
                                  instruct_user_id, instruct_instance, instruct_command, {'no_args': 'True'}, attack_ip,
                                  local_ip, end_time)
                    new_current_sessions = []
                    for session in current_sessions:
                        if dead_session['session_id'] != session['session_id']:
                            new_current_sessions.append(session)
                    current_sessions = new_current_sessions
            elif instruct_command == 'terminate' or shutdown:
                send_response(rt, {'outcome': 'success', 'status': 'terminating'}, 'True', user_id, task_name,
                              task_context, task_type, instruct_user_id, instruct_instance, instruct_command,
                              instruct_args, attack_ip, local_ip, end_time)
                subprocess.call(["/bin/kill", "-15", "1"], stdout=sys.stderr)
            else:
                if instruct_instance not in metasploit:
                    metasploit[instruct_instance] = havoc_metasploit.call_msf(campaign_id)
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
                m = havoc_metasploit.MetasploitParser(call_function)
                task_response = m.metasploit_parser()
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
    task_type = 'metasploit'
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
        local_ip = get_ip()
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