import re
import json

log_line = "2023-03-14T01:28:08-04:00 AONE_BWC_RTR prerouting: in:1.ether5 out:(unknown 0), src-mac 2c:c8:1b:ca:7b:2d, proto TCP (ACK,FIN), 172.17.103.127:34923->52.88.118.255:80, NAT (172.17.103.127:34923->103.175.130.19:34923)->52.88.118.255:80, len 52"

# Extract relevant fields using regular expressions
timestamp = re.findall(r'^(\S+)', log_line)[0]
event = re.findall(r'^(?:\S+ )?(\S+)', log_line)[0]
input_interface = re.findall(r'in:(\S+)', log_line)[0]
output_interface = re.findall(r'out:\((\S+)', log_line)[0]
src_mac = re.findall(r'src-mac (\S+)', log_line)[0]
protocol = re.findall(r'proto (\S+)', log_line)[0]
tcp_flags = re.findall(r'TCP \((\S+)\)', log_line)[0]
src_ip, src_port, dest_ip, dest_port = re.findall(r'(\S+):(\d+)->(\S+):(\d+)', log_line)[0]
nat_ip, nat_port = re.findall(r'NAT \((\S+):(\d+)->(\S+):(\d+)\)', log_line)[0][2:4]
length = re.findall(r'len (\d+)$', log_line)[0]

# Create dictionary with extracted fields
log_dict = {
    "Timestamp": timestamp,
    "Event": event,
    "Input Interface": input_interface,
    "Output Interface": output_interface,
    "Source MAC": src_mac,
    "Protocol": protocol,
    "TCP Flags": tcp_flags,
    "Source IP address": src_ip,
    "Source Port": src_port,
    "Destination IP address": dest_ip,
    "Destination Port": dest_port,
    "NAT IP": nat_ip,
    "NAT PORT": nat_port,
    "Length": length
}
json_log = json.dumps(log_dict, indent=4)
print(json_log)