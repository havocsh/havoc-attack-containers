import os
import re
import shutil
import subprocess
from pymetasploit3.msfrpc import *


class call_msf:

    def __init__(self, campaign_id):
        self.campaign_id = campaign_id
        self.args = None
        self.host_info = None
        self.__msf_client = None
        self.exploit_module = None
        self.payload_module = None
        self.exploit = None
        self.exploit_results = None
        self.exploit_console_results = None
        self.payload = None

    @property
    def msf_client(self):
        """Returns the MsfRpcClient session (establishes one automatically if one does not already exist)"""
        if self.__msf_client is None:
            self.__msf_client = MsfRpcClient(self.campaign_id, ssl=True)
        return self.__msf_client

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname] + local_ip
        return True

    def list_exploits(self):
        exploits = self.msf_client.modules.exploits
        output = {'exploits': exploits, 'forward_log': 'False'}
        return output

    def list_payloads(self):
        payloads = self.msf_client.modules.payloads
        output = {'payloads': payloads, 'forward_log': 'False'}
        return output

    def list_jobs(self):
        jobs = self.msf_client.jobs.list
        output = {'jobs': jobs, 'forward_log': 'False'}
        return output

    def list_sessions(self):
        sessions = self.msf_client.sessions.list
        output = {'sessions': sessions, 'forward_log': 'False'}
        return output

    def set_exploit_module(self):
        try:
            self.exploit_module = self.args['exploit_module']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify exploit_module', 'forward_log': 'False'}
            return output
        try:
            self.exploit = self.msf_client.modules.use('exploit', self.exploit_module)
            output = {'outcome': 'success', 'forward_log': 'False'}
        except:
            output = {'outcome': 'failed', 'message': 'Invalid exploit_module', 'forward_log': 'False'}
            return output
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
                output = {'outcome': 'success', 'forward_log': 'False'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid option or option value', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module must be set before running set_exploit_options',
                      'forward_log': 'False'}
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
                output = {'outcome': 'success', 'forward_log': 'False'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid exploit_target', 'forward_log': 'False'}
                return output
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module must be set before running set_exploit_target',
                      'forward_log': 'False'}
        return output

    def set_payload_module(self):
        try:
            self.payload_module = self.args['payload_module']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify payload_module', 'forward_log': 'False'}
            return output
        try:
            self.payload = self.msf_client.modules.use('payload', self.payload_module)
            output = {'outcome': 'success', 'forward_log': 'False'}
        except:
            output = {'outcome': 'failed', 'message': 'Invalid payload', 'forward_log': 'False'}
        return output

    def set_payload_options(self):
        if self.payload:
            try:
                for key, value in self.args.items():
                    self.payload[key] = value
                output = {'outcome': 'success', 'forward_log': 'False'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid option or option value', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module must be set before running set_payload_options',
                      'forward_log': 'False'}
        return output

    def show_exploit(self):
        if self.exploit:
            output = {'exploit': self.exploit, 'description': self.exploit.description, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit', 'forward_log': 'False'}
        return output

    def show_exploit_options(self):
        if self.exploit:
            options = self.exploit.options
            if options:
                output = {'options': options, 'forward_log': 'False'}
            else:
                output = {'options': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit_options',
                      'forward_log': 'False'}
        return output

    def show_exploit_option_info(self):
        if self.exploit:
            try:
                option = self.args['exploit_option']
            except:
                output = {'message': 'instruct_args must specify exploit_option', 'forward_log': 'False'}
                return output
            try:
                option_info = self.exploit.optioninfo(option)
            except:
                output = {'message': 'invalid exploit_option', 'forward_log': 'False'}
                return output
            if option_info:
                output = {'option_info': option_info, 'forward_log': 'False'}
            else:
                output = {'option_info': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit_option_info',
                      'forward_log': 'False'}
        return output

    def show_exploit_targets(self):
        if self.exploit:
            targets = self.exploit.targets
            if targets:
                output = {'targets': targets, 'forward_log': 'False'}
            else:
                output = {'targets': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit_targets',
                      'forward_log': 'False'}
        return output

    def show_exploit_evasion(self):
        if self.exploit:
            evasion = self.exploit.evasion
            if evasion:
                output = {'evasion': evasion, 'forward_log': 'False'}
            else:
                output = {'evasion': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit_evasion',
                      'forward_log': 'False'}
        return output

    def show_exploit_payloads(self):
        if self.exploit:
            payloads = self.exploit.targetpayloads()
            if payloads:
                output = {'payloads': payloads, 'forward_log': 'False'}
            else:
                output = {'payloads': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit_payloads',
                      'forward_log': 'False'}
        return output

    def show_configured_exploit_options(self):
        if self.exploit:
            run_options = self.exploit.runoptions
            if run_options:
                output = {'options': run_options, 'forward_log': 'False'}
            else:
                output = {'options': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_configured_exploit_options',
                      'forward_log': 'False'}
        return output

    def show_exploit_requirements(self):
        if self.exploit:
            requirements = self.exploit.required
            if requirements:
                output = {'requirements': requirements, 'forward_log': 'False'}
            else:
                output = {'requirements': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_exploit_requirements',
                      'forward_log': 'False'}
        return output

    def show_missing_exploit_requirements(self):
        if self.exploit:
            missing_requirements = self.exploit.missing_required
            if missing_requirements:
                output = {'requirements': missing_requirements, 'forward_log': 'False'}
            else:
                output = {'requirements': None, 'forward_log': 'False'}
        else:
            output = {'message': 'exploit_module must be set before running show_missing_exploit_requirements',
                      'forward_log': 'False'}
        return output

    def show_last_exploit_results(self):
        if self.exploit_results:
            output = {'results': self.exploit_results, 'forward_log': 'False'}
        elif self.exploit_console_results:
            output = {'results': self.exploit_console_results, 'forward_log': 'False'}
        else:
            output = {'results': 'No exploit results found', 'forward_log': 'False'}
        return output

    def show_payload(self):
        if self.payload:
            output = {'payload': self.payload, 'description': self.payload.description, 'forward_log': 'False'}
        else:
            output = {'message': 'payload_module must be set before running show_payload', 'forward_log': 'False'}
        return output

    def show_payload_options(self):
        if self.payload:
            options = self.payload.options
            if options:
                output = {'options': options, 'forward_log': 'False'}
            else:
                output = {'options': None, 'forward_log': 'False'}
        else:
            output = {'message': 'payload_module must be set before running show_payload_options',
                      'forward_log': 'False'}
        return output

    def show_payload_option_info(self):
        if self.payload:
            try:
                option = self.args['payload_option']
            except:
                output = {'message': 'instruct_args must specify payload_option', 'forward_log': 'False'}
                return output
            try:
                option_info = self.payload.optioninfo(option)
            except:
                output = {'message': 'invalid payload_option', 'forward_log': 'False'}
                return output
            if option_info:
                output = {'option_info': option_info, 'forward_log': 'False'}
            else:
                output = {'option_info': None, 'forward_log': 'False'}
        else:
            output = {'message': 'payload_module must be set before running show_payload_option_info',
                      'forward_log': 'False'}
        return output

    def show_configured_payload_options(self):
        if self.payload:
            run_options = self.payload.runoptions
            if run_options:
                output = {'options': run_options, 'forward_log': 'False'}
            else:
                output = {'options': None, 'forward_log': 'False'}
        else:
            output = {'message': 'payload_module must be set before running show_configured_payload_options',
                      'forward_log': 'False'}
        return output

    def show_payload_requirements(self):
        if self.payload:
            requirements = self.payload.required
            if requirements:
                output = {'requirements': requirements, 'forward_log': 'False'}
            else:
                output = {'requirements': None, 'forward_log': 'False'}
        else:
            output = {'message': 'payload_module must be set before running show_payload_requirements',
                      'forward_log': 'False'}
        return output

    def show_missing_payload_requirements(self):
        if self.payload:
            missing_requirements = self.payload.missing_required
            if missing_requirements:
                output = {'requirements': missing_requirements, 'forward_log': 'False'}
            else:
                output = {'requirements': None, 'forward_log': 'False'}
        else:
            output = {'message': 'payload_module must be set before running show_missing_payload_requirements',
                      'forward_log': 'False'}
        return output

    def show_job_info(self):
        try:
            job_id = self.args['job_id']
        except:
            output = {'message': 'instruct_args must specify job_id', 'forward_log': 'False'}
            return output
        job_list = self.msf_client.jobs.list
        if job_id in job_list:
            job_info = self.msf_client.jobs.info(job_id)
            output = {'job_id': job_id, 'job_info': job_info, 'forward_log': 'False'}
        else:
            output = {'message': 'job_id not found', 'forward_log': 'False'}
        return output

    def show_session_info(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            session_info = self.msf_client.sessions.session(session_id).info
            output = {'session_id': session_id, 'session_info': session_info, 'forward_log': 'False'}
        else:
            output = {'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def execute_exploit(self):
        if self.exploit and self.payload:
            try:
                self.exploit_results = self.exploit.execute(payload=self.payload)
            except:
                output = {'outcome': 'failed', 'message': 'Check exploit_options and try again', 'forward_log': 'False'}
                return output
            if 'job_id' in self.exploit_results:
                exploit_module = self.exploit.modulename
                exploit_options = self.exploit.runoptions
                payload_module = self.payload.modulename
                payload_options = self.payload.runoptions
                output = {'outcome': 'success', 'results': self.exploit_results, 'exploit_module': exploit_module,
                          'payload_module': payload_module, 'exploit_options': exploit_options,
                          'payload_options': payload_options, 'forward_log': 'True'}
            else:
                cid = self.msf_client.consoles.console().cid
                self.exploit_console_results = self.msf_client.consoles.console(cid).run_module_with_output(self.exploit, payload=self.payload)
                output = {'outcome': 'failed', 'stdout': self.exploit_console_results, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'exploit_module and payload_module must be set before running execute_exploit',
                      'forward_log': 'False'}
        return output

    def generate_payload(self):
        if self.payload:
            try:
                data = self.payload.payload_generate()
            except:
                output = {'outcome': 'failed', 'message': 'Check required payload options and try again',
                          'forward_log': 'False'}
                return output
            if isinstance(data, str):
                output = {'outcome': 'success', 'payload': data, 'forward_log': 'True'}
            else:
                try:
                    filename = self.args['filename']
                except:
                    output = {'outcome': 'failed', 'message': 'instruct_args must specify filename',
                              'forward_log': 'False'}
                    return output
                with open('/opt/havocops/shared/' + filename, 'wb') as f:
                    f.write(data)
                output = {'outcome': 'success', 'payload': 'Executable file written to /opt/havocops/shared/' + filename, 'forward_log': 'True'}
        else:
            output = {'outcome': 'failed', 'message': 'payload_module must be set before running generate_payload',
                      'forward_log': 'False'}
        return output

    def run_session_command(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            session_command = self.args['session_command']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_command', 'forward_log': 'False'}
            return output
        if 'end_strings' in self.args:
            end_strings = self.args['end_strings']
        else:
            end_strings = None
        if 'timeout' in self.args:
            timeout = self.args['timeout']
        else:
            timeout = None
        if 'timeout_exception' in self.args:
            timeout_exception = self.args['timeout_exception']
        else:
            timeout_exception = None
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                run_session_command_output = self.msf_client.sessions.session(session_id).run_with_output(session_command, end_strings, timeout, timeout_exception)
                output = {'outcome': 'success', 'run_session_command_output': run_session_command_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid session_command', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def run_session_shell_command(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            session_shell_command = self.args['session_shell_command']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_shell_command', 'forward_log': 'False'}
            return output
        if 'end_strings' in self.args:
            end_strings = self.args['end_strings']
        else:
            end_strings = None
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                run_session_shell_command_output = self.msf_client.sessions.session(session_id).run_shell_cmd_with_output(session_shell_command, end_strings)
                output = {'outcome': 'success', 'run_session_shell_command_output': run_session_shell_command_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid session_shell_command', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def session_tabs(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            session_command = self.args['session_command']
        except:
            output = {'message': 'instruct_args must specify session_command', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                session_tabs_output = self.msf_client.sessions.session(session_id).tabs(session_command)
                output = {'session_tabs_output': session_tabs_output, 'session_in': session_id, 'session_info': session_info, 'forward_log': 'False'}
            except:
                output = {'message': 'Invalid session_command', 'forward_log': 'False'}
        else:
            output = {'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def load_session_plugin(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            plugin_name = self.args['plugin_name']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify plugin_name', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                load_session_plugin_output = self.msf_client.sessions.session(session_id).load_plugin(plugin_name)
                output = {'outcome': 'success', 'load_session_plugin_output': load_session_plugin_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'False'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid plugin_name', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def session_import_psh(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            script_name = self.args['script_name']
            script = f'/opt/havocops/shared/{script_name}'
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify script_path', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                session_import_psh_output = self.msf_client.sessions.session(session_id).import_psh(script)
                output = {'outcome': 'success', 'session_import_psh_output': session_import_psh_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid script_path', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def session_run_psh_cmd(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            ps_cmd = self.args['ps_cmd']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify ps_cmd', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                session_run_psh_cmd_output = self.msf_client.sessions.session(session_id).run_psh_cmd(ps_cmd)
                output = {'outcome': 'success', 'session_run_psh_cmd_output': session_run_psh_cmd_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'message': 'Invalid ps_cmd', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'session_id not found', 'forward_log': 'False'}
        return output

    def run_session_script(self):
        try:
            session_id = self.args['session_id']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify session_id', 'forward_log': 'False'}
            return output
        try:
            script_name = self.args['script_name']
            script = f'/opt/havocops/shared/{script_name}'
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify script_name', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                run_session_script_output = self.msf_client.sessions.session(session_id).runscript(script)
                output = {'outcome': 'success', 'run_session_script_output': run_session_script_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'message': 'script_name not found in shared directory', 'forward_log': 'False'}
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
                session_info = self.msf_client.sessions.session(session_id).info
                get_session_writeables_dir_output = self.msf_client.sessions.session(session_id).get_writeable_dir()
                output = {'outcome': 'success', 'get_session_writeables_dir_output': get_session_writeables_dir_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'message': 'session_writeable_dir not found', 'forward_log': 'False'}
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
            session_info = self.msf_client.sessions.session(session_id).info
            session_read_output = self.msf_client.sessions.session(session_id).read()
            output = {'outcome': 'success', 'session_read_output': session_read_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'False'}
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
                session_info = self.msf_client.sessions.session(session_id).info
                session_detach_output = self.msf_client.sessions.session(session_id).detach()
                output = {'outcome': 'success', 'session_detach_output': session_detach_output, 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'forward_log': 'False'}
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
                session_info = self.msf_client.sessions.session(session_id).info
                self.msf_client.sessions.session(session_id).kill()
                output = {'outcome': 'success', 'session_id': session_id, 'session_info': session_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'forward_log': 'False'}
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
                job_info = self.msf_client.jobs.info(job_id)
                self.msf_client.jobs.stop(job_id)
                output = {'outcome': 'success', 'job_id': job_id, 'job_info': job_info, 'forward_log': 'True'}
            except:
                output = {'outcome': 'failed', 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'job_id not found', 'forward_log': 'False'}
        return output
    
    def cert_gen(self):
        if 'subj' not in self.args and 'domain' not in self.args:
            output = {'outcome': 'failed', 'message': 'Missing subj or domain', 'forward_log': 'False'}
            return output
        if 'subj' in self.args and 'domain' in self.args:
            output = {'outcome': 'failed', 'message': 'Specify subj or domain but not both', 'forward_log': 'False'}
            return output
        if 'subj' in self.args:
            subj = self.args['subj']
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
                output = {
                    'outcome': 'success',
                    'message': 'unified certificate file: /opt/havoc/unified.pem',
                    'forward_log': 'True'
                }
            return output
        if 'domain' in self.args:
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
                output = {
                    'outcome': 'success',
                    'message': 'unified certificate file: /opt/havoc/unified.pem',
                    'forward_log': 'True'
                }
            return output

    def session_status_monitor(self):
        current_sessions = self.args['current_sessions']
        new_sessions = []
        dead_sessions = []
        list_sessions = self.list_sessions()
        if 'sessions' in list_sessions:
            sessions_status = list_sessions['sessions']
            current_sessions_id = []
            for current in current_sessions:
                current_sessions_id.append(current)
            temp_sessions_id = []
            for session in sessions_status:
                temp_sessions_id.append(session)

            for session in sessions_status:
                if session not in current_sessions_id:
                    sessions_status[session]['session_id'] = session
                    new_sessions.append(sessions_status[session])
            for current in current_sessions:
                if current not in temp_sessions_id:
                    current_sessions[current]['session_id'] = current
                    dead_sessions.append(current_sessions[current])
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