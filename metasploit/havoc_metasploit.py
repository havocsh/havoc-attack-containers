import os
import re
import base64
import shutil
import subprocess
import time as t
from pymetasploit3.msfrpc import *


class call_msf:

    def __init__(self, campaign_id):
        self.campaign_id = campaign_id
        self.args = None
        self.host_info = None
        self.__msf_client = None
        self.auxiliary_module = None
        self.exploit_module = None
        self.payload_module = None
        self.auxiliary = None
        self.auxiliary_results = None
        self.auxiliary_console_results = None
        self.exploit = None
        self.exploit_results = None
        self.exploit_console_results = None
        self.payload = None
        self.shells = {}

    @property
    def msf_client(self):
        """Returns the MsfRpcClient session (establishes one automatically if one does not already exist)"""
        if self.__msf_client is None:
            self.__msf_client = MsfRpcClient(self.campaign_id, ssl=True)
        return self.__msf_client

    def set_args(self, args, public_ip, hostname, local_ip):
        self.args = args
        self.host_info = [public_ip, hostname] + local_ip
        return True

    def list_auxiliary(self):
        auxiliary = self.msf_client.modules.auxiliary
        output = {'list_auxiliary': auxiliary, 'forward_log': 'False'}
        return output
    
    def list_exploits(self):
        exploits = self.msf_client.modules.exploits
        output = {'list_exploits': exploits, 'forward_log': 'False'}
        return output

    def list_payloads(self):
        payloads = self.msf_client.modules.payloads
        output = {'list_payloads': payloads, 'forward_log': 'False'}
        return output

    def list_jobs(self):
        jobs = self.msf_client.jobs.list
        output = {'list_jobs': jobs, 'forward_log': 'False'}
        return output

    def list_sessions(self):
        sessions = self.msf_client.sessions.list
        output = {'list_sessions': sessions, 'forward_log': 'False'}
        return output

    def modify_routes(self):
        autoroute = self.msf_client.modules.use('post', 'multi/manage/autoroute')
        try:
            output = {'outcome': 'success', 'modify_routes': {}, 'forward_log': 'False'}
            for key, value in self.args.items():
                if key == 'SESSION':
                    autoroute[key] = int(value)
                else:
                    autoroute[key] = value
                output['modify_routes'][key] = value
            autoroute_response = autoroute.execute()
            output['modify_routes']['result'] = autoroute_response
        except Exception as e:
            output = {'outcome': 'failed', 'message': f'modify_route failed with error: {e}', 'forward_log': 'False'}
        return output

    def run_auxiliary(self):
        set_auxiliary_module_results = self.set_auxiliary_module()
        if set_auxiliary_module_results['outcome'] == 'failed':
            message = set_auxiliary_module_results['message']
            output = {'outcome': 'failed', 'message': f'run_auxiliary failed with error: {message}', 'forward_log': 'False'}
            return output
        if 'auxiliary_options' in self.args:
            for key, value in self.args['auxiliary_options'].items():
                if key == 'RHOSTS':
                    if value in self.host_info:
                        output = {'outcome': 'failed', 'message': 'Invalid RHOST value', 'host_info': self.host_info, 'forward_log': 'False'}
                        return output
                self.auxiliary[key] = value
        execute_auxiliary_results = self.execute_auxiliary()
        if execute_auxiliary_results['outcome'] == 'failed':
            message = execute_auxiliary_results['message']
            output = {'outcome': 'failed', 'message': f'run_auxiliary failed with error: {message}', 'forward_log': 'False'}
            return output
        output = {'outcome': 'success', 'run_auxiliary': {'results': execute_auxiliary_results}, 'forward_log': 'False'}
        return output
    
    def run_exploit(self):
        set_exploit_module_results = self.set_exploit_module()
        if set_exploit_module_results['outcome'] == 'failed':
            message = set_exploit_module_results['message']
            output = {'outcome': 'failed', 'message': f'run_exploit failed with error: {message}', 'forward_log': 'False'}
            return output
        if 'exploit_options' in self.args:
            for key, value in self.args['exploit_options'].items():
                if key == 'RHOSTS':
                    if value in self.host_info:
                        output = {'outcome': 'failed', 'message': 'Invalid RHOST value', 'host_info': self.host_info, 'forward_log': 'False'}
                        return output
                self.exploit[key] = value
        if 'exploit_target' in self.args:
            try:
                self.exploit.target = self.args['exploit_target']
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'run_exploit failed while setting exploit target: {e}', 'forward_log': 'False'}
        set_payload_module_results = self.set_payload_module()
        if set_payload_module_results['outcome'] == 'failed':
            message = set_payload_module_results['message']
            output = {'outcome': 'failed', 'message': f'run_exploit failed with error: {message}', 'forward_log': 'False'}
            return output
        if 'payload_options' in self.args:
            for key, value in self.args['payload_options'].items():
                self.payload[key] = value
        execute_exploit_results = self.execute_exploit()
        if execute_exploit_results['outcome'] == 'failed':
            message = execute_exploit_results['message']
            output = {'outcome': 'failed', 'message': f'run_exploit failed with error: {message}', 'forward_log': 'False'}
            return output
        output = {'outcome': 'success', 'run_exploit': {'results': execute_exploit_results}, 'forward_log': 'False'}
        return output
    
    def set_auxiliary_module(self):
        try:
            self.auxiliary_module = self.args['auxiliary_module']
            self.auxiliary = self.msf_client.modules.use('auxiliary', self.auxiliary_module)
            output = {'outcome': 'success', 'set_auxiliary_module': self.auxiliary_module, 'forward_log': 'False'}
        except Exception as e:
            output = {'outcome': 'failed', 'message': f'set_auxiliary_module failed with error: {e}', 'forward_log': 'False'}
        return output
    
    def set_auxiliary_options(self):
        if self.auxiliar:
            try:
                for key, value in self.args.items():
                    if key == 'RHOSTS':
                        if value in self.host_info:
                            output = {'outcome': 'failed', 'message': 'Invalid RHOST value', 'host_info': self.host_info, 'forward_log': 'False'}
                            return output
                    self.auxiliary[key] = value
                output = {'outcome': 'success', 'set_auxiliary_options': self.args, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'set_auxiliary_options failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output
    
    def set_exploit_module(self):
        try:
            self.exploit_module = self.args['exploit_module']
            self.exploit = self.msf_client.modules.use('exploit', self.exploit_module)
            output = {'outcome': 'success', 'set_exploit_module': self.exploit_module, 'forward_log': 'False'}
        except Exception as e:
            output = {'outcome': 'failed', 'message': f'set_exploit_module failed with error: {e}', 'forward_log': 'False'}
        return output

    def set_exploit_options(self):
        if self.exploit:
            try:
                for key, value in self.args.items():
                    if key == 'RHOSTS':
                        if value in self.host_info:
                            output = {'outcome': 'failed', 'message': 'Invalid RHOST value', 'host_info': self.host_info, 'forward_log': 'False'}
                            return output
                    self.exploit[key] = value
                output = {'outcome': 'success', 'set_exploit_options': self.args, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'set_exploit_options failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def set_exploit_target(self):
        if self.exploit:
            try:
                exploit_target = self.args['exploit_target']
            except:
                output = {'outcome': 'failed', 'message': 'instruct_args must specify exploit_target', 'forward_log': 'False'}
                return output
            try:
                self.exploit.target = exploit_target
                output = {'outcome': 'success', 'set_exploit_target': exploit_target, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'set_exploit_target failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def set_payload_module(self):
        try:
            self.payload_module = self.args['payload_module']
        except Exception as e:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify payload_module', 'forward_log': 'False'}
            return output
        try:
            self.payload = self.msf_client.modules.use('payload', self.payload_module)
            output = {'outcome': 'success', 'set_payload_module': self.payload_module, 'forward_log': 'False'}
        except Exception as e:
            output = {'outcome': 'failed', 'message': f'set_payload_module failed with error: {e}', 'forward_log': 'False'}
        return output

    def set_payload_options(self):
        if self.payload:
            try:
                for key, value in self.args.items():
                    self.payload[key] = value
                output = {'outcome': 'success', 'set_payload_options': self.args, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'set_payload_options failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_auxiliary(self):
        if self.auxiliary:
            module_name = self.auxiliary.modulname
            description = f'{self.auxiliary.name} - {self.auxiliary.description}'
            output = {'outcome': 'success', 'show_auxiliary': {'module_name': module_name, 'description': description}, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output
    
    def show_auxiliary_options(self):
        if self.auxiliary:
            options = self.auxiliary.options
            output = {'outcome': 'success', 'show_auxiliary_options': options, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output

    def show_auxiliary_option_info(self):
        if self.auxiliary:
            try:
                option = self.args['auxiliary_option']
            except Exception as e:
                output = {'outcome': 'failed', 'message': 'instruct_args must specify auxiliary_option', 'forward_log': 'False'}
                return output
            try:
                option_info = self.auxiliary.optioninfo(option)
                output = {'outcome': 'success', 'show_auxiliary_option_info': option_info, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'show_auxiliary_option_info failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output
    
    def show_auxiliary_evasion(self):
        if self.auxiliary:
            evasion = self.auxiliary.evasion
            output = {'outcome': 'success', 'show_auxiliary_evasion': evasion, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output
    
    def show_configured_auxiliary_options(self):
        if self.auxiliary:
            run_options = self.auxiliary.runoptions
            output = {'outcome': 'success', 'show_configured_auxiliary_options': run_options, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output

    def show_auxiliary_requirements(self):
        if self.auxiliary:
            requirements = self.auxiliary.required
            output = {'outcome': 'success', 'show_auxiliary_requirements': requirements, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output

    def show_missing_auxiliary_requirements(self):
        if self.auxiliary:
            missing_requirements = self.auxiliary.missing_required
            output = {'outcome': 'success', 'show_missing_auxiliary_requirements': missing_requirements, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output

    def show_last_auxiliary_results(self):
        if self.auxiliary_results:
            output = {'outcome': 'success', 'show_last_auxiliary_results': self.auxiliary_results, 'forward_log': 'False'}
        elif self.exploit_console_results:
            output = {'outcome': 'success', 'show_last_auxiliary_results': self.auxiliary_console_results, 'forward_log': 'False'}
        else:
            output = {'outcome': 'success', 'show_last_auxiliary_results': 'No auxiliary results found', 'forward_log': 'False'}
        return output
    
    def show_exploit(self):
        if self.exploit:
            module_name = self.exploit.modulname
            description = f'{self.exploit.name} - {self.exploit.description}'
            output = {'outcome': 'success', 'show_exploit': {'module_name': module_name, 'description': description}, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_exploit_options(self):
        if self.exploit:
            options = self.exploit.options
            output = {'outcome': 'success', 'show_exploit_options': options, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_exploit_option_info(self):
        if self.exploit:
            try:
                option = self.args['exploit_option']
            except Exception as e:
                output = {'outcome': 'failed', 'message': 'instruct_args must specify exploit_option', 'forward_log': 'False'}
                return output
            try:
                option_info = self.exploit.optioninfo(option)
                output = {'outcome': 'success', 'show_exploit_option_info': option_info, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'show_exploit_option_info failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_exploit_targets(self):
        if self.exploit:
            targets = self.exploit.targets
            output = {'outcome': 'success', 'show_exploit_targets': targets, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_exploit_evasion(self):
        if self.exploit:
            evasion = self.exploit.evasion
            output = {'outcome': 'success', 'show_exploit_evasion': evasion, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_exploit_payloads(self):
        if self.exploit:
            payloads = self.exploit.targetpayloads()
            output = {'outcome': 'success', 'show_exploit_payloads': payloads, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_configured_exploit_options(self):
        if self.exploit:
            run_options = self.exploit.runoptions
            output = {'outcome': 'success', 'show_configured_exploit_options': run_options, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_exploit_requirements(self):
        if self.exploit:
            requirements = self.exploit.required
            output = {'outcome': 'success', 'show_exploit_requirements': requirements, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_missing_exploit_requirements(self):
        if self.exploit:
            missing_requirements = self.exploit.missing_required
            output = {'outcome': 'success', 'show_missing_exploit_requirements': missing_requirements, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module not set', 'forward_log': 'False'}
        return output

    def show_last_exploit_results(self):
        if self.exploit_results:
            output = {'outcome': 'success', 'show_last_exploit_results': self.exploit_results, 'forward_log': 'False'}
        elif self.exploit_console_results:
            output = {'outcome': 'success', 'show_last_exploit_results': self.exploit_console_results, 'forward_log': 'False'}
        else:
            output = {'outcome': 'success', 'show_last_exploit_results': 'No exploit results found', 'forward_log': 'False'}
        return output

    def show_payload(self):
        if self.payload:
            module_name = self.payload.modulname
            description = f'{self.payload.name} - {self.payload.description}'
            output = {'outcome': 'success', 'show_payload': {'module_name': module_name, 'description': description}, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_payload_options(self):
        if self.payload:
            options = self.payload.options
            output = {'outcome': 'success', 'show_payload_options': options, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_payload_option_info(self):
        if self.payload:
            try:
                option = self.args['payload_option']
            except:
                output = {'outcome': 'failed', 'message': 'instruct_args must specify payload_option', 'forward_log': 'False'}
                return output
            try:
                option_info = self.payload.optioninfo(option)
                output = {'outcome': 'success', 'show_payload_option_info': option_info, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'show_payload_option_info failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_configured_payload_options(self):
        if self.payload:
            run_options = self.payload.runoptions
            output = {'outcome': 'success', 'show_configured_payload_options': run_options, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_payload_requirements(self):
        if self.payload:
            requirements = self.payload.required
            output = {'outcome': 'success', 'show_payload_requirements': requirements, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_missing_payload_requirements(self):
        if self.payload:
            missing_requirements = self.payload.missing_required
            output = {'outcome': 'success', 'show_missing_payload_requirements': missing_requirements, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def show_job_info(self):
        try:
            job_id = self.args['job_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify job_id', 'forward_log': 'False'}
            return output
        job_list = self.msf_client.jobs.list
        if job_id in job_list:
            job_info = self.msf_client.jobs.info(job_id)
            output = {'outcome': 'success', 'show_job_info': job_info, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'job_id not found', 'forward_log': 'False'}
        return output

    def show_session_info(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            session_info = self.msf_client.sessions.session(session_id).info
            output = {'outcome': 'success', 'show_session_info': session_info, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def execute_auxiliary(self):
        if self.auxiliary:
            try:
                self.auxiliary_results = self.auxiliary.execute()
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'execute_auxiliary failed with error: {e}', 'forward_log': 'False'}
                return output
            if 'job_id' in self.auxiliary_results:
                output = {'outcome': 'success', 'execute_auxiliary': {'results': self.auxiliary_results}, 'forward_log': 'True'}
            else:
                cid = self.msf_client.consoles.console().cid
                self.auxiliary_console_results = self.msf_client.consoles.console(cid).run_module_with_output(self.auxiliary)
                output = {'outcome': 'failed', 'message': self.auxiliary_console_results, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'auxiliary_module not set', 'forward_log': 'False'}
        return output
    
    def execute_exploit(self):
        if self.exploit and self.payload:
            try:
                self.exploit_results = self.exploit.execute(payload=self.payload)
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'execute_exploit failed with error: {e}', 'forward_log': 'False'}
                return output
            if 'job_id' in self.exploit_results:
                output = {'outcome': 'success', 'execute_exploit': {'results': self.exploit_results}, 'forward_log': 'True'}
            else:
                cid = self.msf_client.consoles.console().cid
                self.exploit_console_results = self.msf_client.consoles.console(cid).run_module_with_output(self.exploit, payload=self.payload)
                output = {'outcome': 'failed', 'message': self.exploit_console_results, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module or payload_module not set', 'forward_log': 'False'}
        return output

    def generate_payload(self):
        if self.payload:
            if self.args:
                for k, v in self.args.items():
                    if k in self.payload.options:
                        self.payload[k] = v
            try:
                data = self.payload.payload_generate()
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'generate_payload failed with error: {e}', 'forward_log': 'False'}
                return output
            if 'file_name' in self.args:
                try:
                    file_name = self.args['file_name']
                    with open(f'/opt/havoc/shared/{file_name}', 'wb') as f:
                        f.write(data)
                    output = {'outcome': 'success', 'generate_payload': {'file_name': file_name}, 'forward_log': 'True'}
                except Exception as e:
                    output = {'outcome': 'failed', 'message': f'generate_payload failed with error: {e}', 'forward_log': 'False'}
            else:
                output = {'outcome': 'success', 'generate_payload': {'payload': base64.b64encode(data.decode())}, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module not set', 'forward_log': 'False'}
        return output

    def run_session_command(self):
        req_args = ['session_id', 'session_command']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output    
        session_id = self.args['session_id']
        session_command = self.args['session_command']
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                run_session_command_output = self.msf_client.sessions.session(session_id).run_with_output(session_command)
                output = {'outcome': 'success', 'run_session_command': {'results': run_session_command_output}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'run_session_command failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def run_session_shell_command(self):

        def send_shell_command(command):
            shell_read = None
            self.shells[session_id].write(command)
            while not shell_read:
                shell_read = self.shells[session_id].read()
            return shell_read
        
        req_args = ['session_id', 'session_shell_command']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output
        session_id = self.args['session_id']
        session_shell_command = self.args['session_shell_command']
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_type = session_list[session_id]['type']
                if session_id not in self.shells:
                    self.shells[session_id] = self.msf_client.sessions.session(session_id)
                    if session_type != 'shell':
                        send_shell_command('shell')
                command_output = send_shell_command(session_shell_command)
                if '/bin/sh:' in command_output or 'invalid option' in command_output or 'Unknown command:' in command_output:
                    output = {'outcome': 'failed', 'message': command_output, 'forward_log': 'False'}
                else:
                    output = {'outcome': 'success', 'run_session_shell_command': {'results': command_output}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'run_session_shell_command failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': f'session_id not found: {session_list}', 'forward_log': 'False'}
        return output

    def session_tabs(self):
        req_args = ['session_id', 'session_command']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output  
        session_id = self.args['session_id']
        session_command = self.args['session_command']
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_tabs_output = self.msf_client.sessions.session(session_id).tabs(session_command)
                output = {'outcome': 'success', 'session_tabs': {'results': session_tabs_output}, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'session_tabs failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def load_session_plugin(self):
        req_args = ['session_id', 'plugin_name']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output  
        session_id = self.args['session_id']
        plugin_name = self.args['plugin_name']
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                load_session_plugin_output = self.msf_client.sessions.session(session_id).load_plugin(plugin_name)
                output = {'outcome': 'success', 'load_session_plugin': {'results': load_session_plugin_output}, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'load_session_plugin failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def session_import_psh(self):
        req_args = ['session_id', 'script_name']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output 
        session_id = self.args['session_id']
        script_name = self.args['script_name']
        script = f'/opt/havoc/shared/{script_name}'
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_import_psh_output = self.msf_client.sessions.session(session_id).import_psh(script)
                output = {'outcome': 'success', 'session_import_psh': {'results': session_import_psh_output}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'session_import_psh failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def session_run_psh_cmd(self):
        req_args = ['session_id', 'ps_cmd']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output 
        session_id = self.args['session_id']
        ps_cmd = self.args['ps_cmd']
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_run_psh_cmd_output = self.msf_client.sessions.session(session_id).run_psh_cmd(ps_cmd)
                output = {'outcome': 'success', 'session_run_psh_cmd': {'results': session_run_psh_cmd_output}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'session_run_psh_cmd failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def run_session_script(self):
        req_args = ['session_id', 'script_name']
        for req_arg in req_args:
            if req_arg not in self.args:
                output = {'outcome': 'failed', 'message': f'instruct_args must specify {req_arg}', 'forward_log': 'False'}
                return output 
        session_id = self.args['session_id']
        script_name = self.args['script_name']
        script = f'/opt/havoc/shared/{script_name}'
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                run_session_script_output = self.msf_client.sessions.session(session_id).runscript(script)
                output = {'outcome': 'success', 'run_session_script': {'results': run_session_script_output}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'run_session_script failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def get_session_writeable_dir(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                get_session_writeable_dir_output = self.msf_client.sessions.session(session_id).get_writeable_dir()
                output = {'outcome': 'success', 'get_session_writeable_dir': {'results': get_session_writeable_dir_output}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'get_session_writeable_dir failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def session_read(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_read_output = self.msf_client.sessions.session(session_id).read()
                output = {'outcome': 'success', 'session_read': {'results': session_read_output}, 'forward_log': 'False'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'session_read failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def detach_session(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                self.msf_client.sessions.session(session_id).detach()
                output = {'outcome': 'success', 'detach_session': {'session_id': session_id}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'detach_session failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def kill_session(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                if session_id in self.shells:
                    self.shells[session_id].write('exit')
                    self.shells[session_id].stop()
                    del self.shells[session_id]
                else:
                    self.msf_client.sessions.session(session_id).stop()
                output = {'outcome': 'success', 'kill_session': {'session_id': session_id}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'kill_session failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def kill_job(self):
        try:
            job_id = self.args['job_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify job_id', 'forward_log': 'False'}
            return output
        job_list = self.msf_client.jobs.list
        if job_id in job_list:
            try:
                self.msf_client.jobs.stop(job_id)
                output = {'outcome': 'success', 'kill_job': {'job_id': job_id}, 'forward_log': 'True'}
            except Exception as e:
                output = {'outcome': 'failed', 'message': f'kill_job failed with error: {e}', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'job_id not found', 'forward_log': 'False'}
        return output
    
    def cert_gen(self):
        if 'cert_type' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing cert_type', 'forward_log': 'False'}
            return output
        cert_type = self.args['cert_type']
        if cert_type == 'self-signed':
            required_params = ['cert_country', 'cert_state', 'cert_locale', 'cert_org', 'cert_org_unit', 'cert_host']
            for param in required_params:
                if param not in self.args:
                    output = {'outcome': 'failed', 'message': f'Missing {param}', 'forward_log': 'False'}
                    return output
            cert_country = self.args['cert_country']
            cert_state = self.args['cert_state']
            cert_locale = self.args['cert_locale']
            cert_org = self.args['cert_org']
            cert_org_unit = self.args['cert_org_unit']
            cert_host = self.args['cert_host']
            if cert_host == 'public_ip':
                host = self.host_info[0]
            if cert_host == 'local_ip':
                host = self.host_info[2]
            subj = f'/C={cert_country}/ST={cert_state}/L={cert_locale}/O={cert_org}/OU={cert_org_unit}/CN={host}'
            p = subprocess.Popen(
                [
                    '/usr/bin/openssl',
                    'req',
                    '-new',
                    '-x509',
                    '-keyout',
                    '/opt/havoc/private.key',
                    '-out',
                    '/opt/havoc/fullchain.pem',
                    '-days',
                    '365',
                    '-nodes',
                    '-subj',
                    f'{subj}'
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            openssl_out = p.communicate()
            openssl_message = openssl_out[1].decode('utf-8')
            if 'problems making Certificate Request' in openssl_message:
                output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'False'}
                return output
            if os.path.isfile('/opt/havoc/unified.pem'):
                os.remove('/opt/havoc/unified.pem')
            cat = subprocess.Popen(
                [
                    '/bin/cat',
                    '/opt/havoc/private.key',
                    '/opt/havoc/fullchain.pem',
                    '>>',
                    '/opt/havoc/unified.pem'
                ]
            )
            cat_out = cat.communicate()
            if cat_out[1]:
                output = {'outcome': 'failed', 'message': openssl_message, 'forward_log': 'False'}
            else:
                output = {'outcome': 'success', 'cert_gen': {'host': host, 'subj': subj}, 'forward_log': 'True'}
            return output
        if cert_type == 'ca-signed':
            if 'domain' not in self.args:
                output = {'outcome': 'failed', 'message': 'Missing domain for certificate registration', 'forward_log': 'False'}
                return output
            if 'email' not in self.args:
                output = {'outcome': 'failed', 'message': 'Missing email for certificate registration', 'forward_log': 'False'}
                return output
            domain = self.args['domain']
            email = self.args['email']
            if 'test_cert' in self.args and self.args['test_cert'].lower() == 'true':
                certbot_command = ['/usr/bin/certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '--test-cert', '-d', domain, '-m', email]
            else:
                certbot_command = ['/usr/bin/certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '-d', domain, '-m', email]
            p = subprocess.Popen(
                certbot_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            certbot_out = p.communicate()
            certbot_message = certbot_out[0].decode('utf-8')
            if 'Successfully received certificate' not in certbot_message:
                output = {'outcome': 'failed', 'message': certbot_message, 'forward_log': 'False'}
                return output
            try:
                shutil.copyfile(f'/etc/letsencrypt/live/{domain}/fullchain.pem', '/opt/havoc/fullchain.pem')
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            try:
                shutil.copyfile(f'/etc/letsencrypt/live/{domain}/privkey.pem', '/opt/havoc/privkey.pem')
            except Exception as e:
                output = {'outcome': 'failed', 'message': e, 'forward_log': 'False'}
                return output
            if os.path.isfile('/opt/havoc/unified.pem'):
                os.remove('/opt/havoc/unified.pem')
            cat = subprocess.Popen(
                [
                    '/bin/cat',
                    '/opt/havoc/privkey.pem',
                    '/opt/havoc/fullchain.pem',
                    '>>',
                    '/opt/havoc/unified.pem'
                ]
            )
            cat_out = cat.communicate()
            if cat_out[1]:
                output = {'outcome': 'failed', 'message': certbot_message, 'forward_log': 'False'}
            else:
                output = {'outcome': 'success', 'cert_gen': {'domain': domain, 'email': email}, 'forward_log': 'True'}
            return output
        output = {'outcome': 'failed', 'message': 'cert_type must be self-signed or ca-signed', 'forward_log': 'False'}
        return output

    def session_status_monitor(self):
        current_sessions = self.args['current_sessions']
        new_sessions = []
        dead_sessions = []
        list_sessions = self.list_sessions()
        if 'list_sessions' in list_sessions:
            sessions_status = list_sessions['list_sessions']
            current_sessions_id = []
            for current in current_sessions:
                current_sessions_id.append(current['session_id'])
            temp_sessions_id = []
            for session in sessions_status.keys():
                temp_sessions_id.append(session)

            for session in sessions_status.keys():
                if session not in current_sessions_id:
                    sessions_status[session]['session_id'] = session
                    new_sessions.append(sessions_status[session])
            for current in current_sessions:
                if current['session_id'] not in temp_sessions_id:
                    dead_sessions.append(current)
        sessions = {'new_sessions': new_sessions, 'dead_sessions': dead_sessions}
        return sessions

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


class MetasploitParser:

    def __init__(self, event):
        self.event = event

    def metasploit_parser(self):
        if 'exploit_options' in self.event:
            if 'RHOSTS' in self.event['exploit_options']:
                rhost_match = re.search('\d+\.\d+\.\d+\.\d+', self.event['exploit_options']['RHOSTS'])
                if rhost_match:
                    self.event['target_ip'] = self.event['exploit_options']['RHOSTS']
                else:
                    self.event['target_hostnames'] = [self.event['exploit_options']['RHOSTS']]
            if 'RPORT' in self.event['exploit_options']:
                self.event['target_port'] = self.event['exploit_options']['RPORT']
        if 'payload_options' in self.event:
            if 'LHOST' in self.event['payload_options']:
                lhost_match = re.search('\d+\.\d+\.\d+\.\d+', self.event['payload_options']['LHOST'])
                if lhost_match:
                    self.event['callback_ip'] = self.event['payload_options']['LHOST']
                else:
                    self.event['callback_hostname'] = self.event['payload_options']['LHOST']
            if 'LPORT' in self.event['payload_options']:
                self.event['callback_port'] = self.event['payload_options']['LPORT']
        if 'session_info' in self.event and 'exploit_options' not in self.event and 'payload_options' not in self.event:
            if 'target_host' in self.event['session_info']:
                target_host_match = re.search('\d+\.\d+\.\d+\.\d+', self.event['session_info']['target_host'])
                if target_host_match:
                    self.event['target_ip'] = self.event['session_info']['target_host']
                else:
                    self.event['target_hostnames'] = [self.event['session_info']['target_host']]
            if 'session_port' in self.event['session_info']:
                self.event['target_port'] = self.event['session_info']['session_port']
        return self.event