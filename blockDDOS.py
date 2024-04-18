from netmiko import ConnectHandler
from datetime import datetime, timedelta
import sys
from scapy.all import *

# Firewall1
device1 = {
    'device_type': 'vyos',
    'ip': '192.1.2.1',  # IP address of the interface of Firewall1
    'username': 'vyos',  # VyOS username
    'password': 'vyos',  # VyOS password
    'port': 22,  # SSH port
}

# Firewall2
device2 = {
    'device_type': 'vyos',
    'ip': '192.1.3.1',  # IP address of The interface of Firewall2
    'username': 'vyos',  # VyOS username
    'password': 'vyos',  # VyOS password
    'port': 22,  # SSH port
}

# Connect to Firewall1 
FW1 = ConnectHandler(**device1)
FW1.enable()

# Connect to Firewall2
FW2 = ConnectHandler(**device2)
FW2.enable()

rule = 18

def detect_ddos(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        current_time = datetime.now()
        # see if ip has already been seen
        if src_ip in src_ip_counter:
            if current_time - src_ip_counter[src_ip]["time"] < timedelta(seconds=10):
                src_ip_counter[src_ip]["count"] += 1
            else:
                src_ip_counter[src_ip]["count"] = 1
            src_ip_counter[src_ip]["time"] = current_time
        else:
            src_ip_counter[src_ip] = {"count": 1, "time": current_time}

        # check if ip has been seen 5 times in the last 10 seconds
        if src_ip_counter[src_ip]["count"] >= 5:
            print(f"Possible DDoS attack detected from {src_ip} with {src_ip_counter[src_ip]} packets.")
            
            # VyOS configuration commands to block the source IP
            config_commands = []
            config_commands.append(f'set firewall name OUTSIDE-TO-DMZ rule {rule} source address {src_ip}')
            config_commands.append(f'set firewall name OUTSIDE-TO-DMZ rule {rule} action drop')
            
            ## send commands to Firewall 1
            output = FW1.send_config_set(config_commands)
            FW1.send_command('commit')
            FW1.send_command('save')

            ## send commands to Firewall 2
            output = FW2.send_config_set(config_commands)
            FW2.send_command('commit')
            FW2.send_command('save')


if __name__ == '__main__':
    src_ip_counter = {}
    sniff(filter='ip', prn=detect_ddos)

