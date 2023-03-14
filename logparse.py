import re
import json
from flask import Flask, render_template, request, redirect, url_for
file = open('ip.log', 'r')
Lines = file.readlines()
output_logs = []
count = 0
# Strips the newline character
for log_line in Lines:
    count += 1
# Extract relevant fields using regular expressions
    timestamp = re.findall(r'^(\S+)', log_line)[0]
    host = re.findall(r'^(?:\S+ )?(\S+)', log_line)[0]
    event = re.findall(r'^(?:\S+ )?(\S+)\ ?(\S+)\:', log_line)[0][1]
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
        "Host": host,
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
    output_logs.append(log_dict)
print(output_logs)
with open("output.json", "w") as f:
    json.dump(output_logs, f, indent=4)

app = Flask(__name__)

@app.route('/')
def index():
    return output_logs

if __name__ == '__main__':
    app.run(debug=True)