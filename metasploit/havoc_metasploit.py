from pymetasploit3.msfrpc import *


class call_msf:

    def __init__(self):
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
            self.__msf_client = MsfRpcClient('1msf_secured2', ssl=True)
        return self.__msf_client

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname, local_ip]
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
            output = {'outcome': 'failed', 'message': 'payload_module must be set before running set_payload_options', 'forward_log': 'False'}
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
            output = {'job_info': job_info, 'forward_log': 'False'}
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
            output = {'session_info': session_info, 'forward_log': 'False'}
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
                run_session_shell_command_output = self.msf_client.sessions.session(session_id).run_with_output(session_shell_command, end_strings)
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
                session_tabs_output = self.msf_client.sessions.session(session_id).tabs(session_command)
                output = {'session_tabs_output': session_tabs_output, 'forward_log': 'False'}
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
                load_session_plugin_output = self.msf_client.sessions.session(session_id).load_plugin(plugin_name)
                output = {'outcome': 'success', 'load_session_plugin_output': load_session_plugin_output, 'forward_log': 'False'}
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
            script_path = self.args['script_path']
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify script_path', 'forward_log': 'False'}
            return output
        session_list = self.msf_client.sessions.list
        if session_id in session_list:
            try:
                session_info = self.msf_client.sessions.session(session_id).info
                session_import_psh_output = self.msf_client.sessions.session(session_id).import_psh(script_path)
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
            session_read_output = self.msf_client.sessions.session(session_id).read()
            output = {'outcome': 'success', 'session_read_output': session_read_output, 'forward_log': 'False'}
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
        print(session_list) #Temporary print statement for debugging
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
