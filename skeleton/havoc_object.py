class call_object:

    def __init__(self):
        self.args = None
        self.host_info = None
        self.results = None

    def set_args(self, args, attack_ip, hostname, local_ip):
        self.args = args
        self.host_info = [attack_ip, hostname, local_ip]
        return True

    def example_command(self):
        pass
