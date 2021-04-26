import nmap


class call_nmap:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname, local_ip]
        return True

    def run_scan(self):
        try:
            target = self.args['target']
            if target in self.host_info:
                output = {'outcome': 'failed', 'message': 'Invalid target value', 'forward_log': 'False'}
                return output
        except:
            output = {'outcome': 'failed', 'message': 'instruct_args must specify target', 'forward_log': 'False'}
            return output
        if 'options' in self.args:
            options = self.args['options']
        else:
            options = None
        nm = nmap.PortScanner()
        try:
            self.results = nm.scan(hosts=target, arguments=options)
            scan = self.results['scan']
            output = {'outcome': 'success', 'scan': scan, 'forward_log': 'True'}
        except:
            output = {'outcome': 'failed', 'message': 'Invalid options', 'forward_log': 'False'}
        return output

    def get_scan_info(self):
        if self.results:
            scan_info = self.results['nmap']
            output = {'outcome': 'success', 'scan_info': scan_info, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'run_nmap must be run before get_scan_info',
                      'forward_log': 'False'}
        return output

    def get_scan_results(self):
        if self.results:
            scan_results = self.results['scan']
            output = {'outcome': 'success', 'scan_results': scan_results, 'forward_log': 'False'}
        else:
            output = {'outcome': 'failed', 'message': 'run_nmap must be run before get_scan_results',
                      'forward_log': 'False'}
        return output

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
