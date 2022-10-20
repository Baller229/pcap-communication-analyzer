from ipaddress import IPv6Address
import statistics
import textwrap
from tkinter import S
from scapy.all import *
from ast import literal_eval   
import yaml
import ruamel.yaml
import re
import json
import string

# DICTIONARIES
PACKETS = []
STATISTICS = []
PACKETS_yaml = []

# HEADER
name = "PKS2022/23";
pcap_name = "pcaps/trace-10.pcap";
file_name = "output/tracetest.yaml";

# CHECKERS
check_SAP = [];
check_PID = [];
check_ETHER_TYPE = [];
check_PROTOCOL = [];
check_APP_PROTOCOL = [];
# ARRAYS
frame_numbers = [0 for x in range(5000)];
hexa_frame = ["" for x in range(5000)];
yaml_hexa_frame = ["" for x in range(5000)];
yaml_hexa_frame_ISL = ["" for x in range(5000)];
len_frame_pcap = [0 for x in range(5000)];
len_frame_medium = [0 for x in range(5000)];
src_mac = [0 for x in range(5000)];
dst_mac = [0 for x in range(5000)];
frame_type = ["" for x in range(5000)];
sap_type = ["" for x in range(5000)];
pid_type = ["" for x in range(5000)];

ether_type = ["" for x in range(5000)];
protocol = ["" for x in range(5000)];
src_ip = ["" for x in range(5000)];
dst_ip = ["" for x in range(5000)];
src_port = ["" for x in range(5000)];
dst_port = ["" for x in range(5000)];
app_protocol = ["" for x in range(5000)];
# ===================================================

# ===================================================
#   DESERIALIZE JSON INTO DICTIONARIES
# ===================================================

with open('json/analyze.json') as json_file:
    data = json.load(json_file)

check_SAP.append(data["sap"]);
check_PID.append(data["pid"]);
check_ETHER_TYPE.append(data["ether_type"]);
check_PROTOCOL.append(data["protocol"]);
check_APP_PROTOCOL.append(data["app_protocol"]);
print(check_PROTOCOL);

# ===================================================
#   READ .pcap FILE AND INITIALIZE FRAME_NUMBER
# ===================================================
packets = rdpcap(pcap_name);
frame_number = 0;
# ===================================================

# ADD NEW LINE EACH SEGMENT OF HEXDUMP
def wrap(string, max_width):
    return '\n'.join(textwrap.wrap(string,max_width))

# ===================================================
#   STATISTIC LIST FOR IPv4 SENDERS
# ===================================================

def find_max_ip_senders(keys, values):
    max_indices = []
    keys_indicies = []
    if values:
        max_val = values[0]
        for i,val in ((i,val) for i,val in enumerate(values) if val >= max_val):
            if val == max_val:
                max_indices.append(i)
            else:
                max_val = val
                max_indices = [i]
        for i in max_indices:
            keys_indicies.append(keys[i])
            print(keys_indicies ,": ", keys)
    return keys_indicies

# ===================================================
#   STATISTIC LIST FOR IPv4 SENDERS
# ===================================================

def count_src_ip_occurrence(a):
    k = {}
    empty = 0;
    for j in a:
        empty = empty + 1
        if(len(j) == 0):
            continue;
        if j in k:
            k[j] +=1
        else:
            k[j] =1
        
    return k

# ===================================================
#   FORMAT APP_PROTOCOL
# ===================================================

def format_app_protocol(port: str, frame_num):
    app_protocol[frame_num] = check_APP_PROTOCOL[0][port];
# ===================================================
#   FORMAT SRC and DST PORT
# ===================================================

def format_src_port(src_port_id, protocol_id: str, frame_num):
    decimal = literal_eval( "0x" + src_port_id)
    if(check_PROTOCOL[0][protocol_id] == "TCP" or check_PROTOCOL[0][protocol_id] == "UDP"):
        try:
            format_app_protocol(str(decimal), frame_num)
        except:
            print("The port for app_protocol is not source port")
    return decimal;

def format_dst_port(dst_port_id: str, protocol_id: str, frame_num):
    decimal = literal_eval( "0x" + dst_port_id)
    if(check_PROTOCOL[0][protocol_id] == "TCP" or check_PROTOCOL[0][protocol_id] == "UDP"):
        try:
            format_app_protocol(str(decimal), frame_num)
        except:
            print("The port for app_protocol is not destination port")
    return decimal;

# ===================================================
#   FORMAT PROTOCOL
# ===================================================

def format_protocol(hexdump: str, protocol_id: str, frame_num):
    if(check_PROTOCOL[0][protocol_id] == "TCP" or check_PROTOCOL[0][protocol_id] == "UDP"):
        
        src_port[frame_num] = format_src_port(hexdump[68:72], protocol_id, frame_num)
        dst_port[frame_num] = format_dst_port(hexdump[72:76], protocol_id, frame_num)
    protocol[frame_num] = check_PROTOCOL[0][protocol_id];

# ===================================================
#   FORMAT SRC_IP
# ===================================================

def format_src_ip(ip: str):
    bytes = ["".join(x) for x in zip(*[iter(ip)]*2)]
    bytes = [int(x, 16) for x in bytes]
    ipAddr = ".".join(str(x) for x in (bytes))
    print("bytes: ", bytes)
    return ipAddr

# ===================================================
#   FORMAT DST_IP
# ===================================================

def format_dst_ip(ip: str):
    bytes = ["".join(x) for x in zip(*[iter(ip)]*2)]
    bytes = [int(x, 16) for x in bytes]
    ipAddr = ".".join(str(x) for x in (bytes))
    print("bytes: ", bytes)
    return ipAddr

# ===================================================
#   FORMAT SRC_MAC
# ===================================================

def format_src_mac(mac: str, frame_num):
    mac = re.sub('[.:-]', '', mac).upper()  
    mac = ''.join(mac.split()) 
    assert len(mac) == 12 
    mac = ":".join(["%s" % (mac[i:i+2]) for i in range(0, 12, 2)])
    src_mac[frame_num] = mac;

# ===================================================
#   FORMAT DST_MAC
# ===================================================

def format_dst_mac(mac: str, frame_num):
    mac = re.sub('[.:-]', '', mac).upper()  
    mac = ''.join(mac.split()) 
    mac = ":".join(["%s" % (mac[i:i+2]) for i in range(0, 12, 2)])
    dst_mac[frame_num] = mac;

# ===================================================
#   FORMAT FRAME_NUMBER
# ===================================================

def format_frame_number(frame_num):
    frame_numbers[frame_num] = frame_num;

# ===================================================
#   FORMAT FRAME_NUMBER
# ===================================================

def format_ether_type(hexdump: str, eth, frame_num):
    if(check_ETHER_TYPE[0][eth] == "IPv4"):
        format_protocol(hexdump, hexdump[46:48], frame_num)
        src_ip[frame_num] = format_src_ip(hexdump[52:60]);
        dst_ip[frame_num] = format_src_ip(hexdump[60:68]);
    if(check_ETHER_TYPE[0][eth] == "ARP"):
        src_ip[frame_num] = format_src_ip(hexdump[52:60]);
        dst_ip[frame_num] = format_src_ip(hexdump[60:68]);

    ether_type[frame_num] = check_ETHER_TYPE[0][eth];

# ===================================================
#   FORMAT HEXDUMP
# ===================================================

def format_hexdump(hex: str) -> str:
    hex = re.sub('', '', hex).upper()
    hex = " ".join(["%s" % (hex[i:i+2]) for i in range(0, len(hex), 2)])
    return  wrap(hex, 48) + '\n'

# ===================================================
#   FORMAT PID
# ===================================================

def format_pid(pid: str, frame_num):
    pid_type[frame_num] = check_PID[0][pid]

# ===================================================
#   FORMAT SRC_MAC
# ===================================================

def format_sap(sap: str, frame_num):
    
    sap_type[frame_num] = check_SAP[0][sap]

# ===================================================
#   FORMAT FRAME_TYPE
# ===================================================
def format_frame_type(hexdump: str, frame_type: str, ieee: str, sap: str, pid: str, frame_num):
    decimal = literal_eval( "0x" + frame_type)
    if(decimal > 1500):
        format_ether_type(hexdump, hexdump[24:28], frame_num);
        return 'Ethernet II'
    else:
        if(ieee == "aa"):
            format_pid(pid, frame_num)
            return "IEEE 802.3 LLC & SNAP"
        elif(ieee == "ff"):
            return "IEEE 802.3 RAW"
        else:
            format_sap(sap, frame_num)
            return "IEEE 802.3 LLC"

# ===================================================
#   FORMAT LEN_FRAME_PCAP
# ===================================================

def format_len_frame_pcap(hexdump: str, frame_num, isl_hexdump_len):
    len_frame_pcap[frame_num] = int((len(hexdump) + + isl_hexdump_len)/2);

# ===================================================
#   FORMAT LEN_FRAME_MEDIUM
# ===================================================

def format_len_frame_medium(hexdump: str,frame_num, isl_hexdump_len):
    if(len_frame_pcap[frame_num] < 60):
        
        len_frame_medium[frame_num] = 64;
    else:
        len_frame_medium[frame_num] = len_frame_pcap[frame_num] + 4;

# ===================================================

def analyze(hexdump: str, frame_num, isl_hexdump_len):
    format_frame_number(frame_num);
    frame_type[frame_num] = format_frame_type(hexdump, hexdump[24:28], hexdump[28:30], hexdump[30:32], hexdump[40:44], frame_num);
    format_len_frame_pcap(hexdump, frame_num, isl_hexdump_len);
    format_len_frame_medium(hexdump, frame_num, isl_hexdump_len);
    format_src_mac(hexdump[12:24], frame_num);
    format_dst_mac(hexdump[0:12], frame_num);
    

# ===================================================

# ===================================================
#   GO THROUGH EACH PACKET IN PACKETS
# ===================================================

for packet in packets:
    frame_number = frame_number + 1;    
    hexa_frame[frame_number] = str(raw(packet).hex());
    # ISL CHECK
    # print(frame_number)
    if(hexa_frame[frame_number][0:12] == "01000c000000"):
        print(frame_number ,": ISL")
        # HEXDUMP
        yaml_hexa_frame_ISL[frame_number] = hexa_frame[frame_number];
        yaml_hexa_frame[frame_number] = format_hexdump(yaml_hexa_frame_ISL[frame_number]);
        hexa_frame[frame_number] = hexa_frame[frame_number][52:];
        
        analyze(hexa_frame[frame_number], frame_number, 52);
    else:
        # HEXDUMP
        yaml_hexa_frame[frame_number] = format_hexdump(hexa_frame[frame_number]);
        
        analyze(hexa_frame[frame_number], frame_number, 0);

    #=======================================================================================
    print(frame_numbers[frame_number], ": pcap: ", len_frame_pcap[frame_number])
    print(frame_numbers[frame_number], ": medium: ", len_frame_medium[frame_number])
    print(frame_numbers[frame_number], ": src_mac: ", src_mac[frame_number])
    print(frame_numbers[frame_number], ": dst_mac: ", dst_mac[frame_number])
    #=======================================================================================




# ===================================================
#   ADD TO DICTIONARY PACKETS[]
# ===================================================
print("res type: ", type(count_src_ip_occurrence(src_ip)));
keys = []
values = []
maxIPSenders = []
for key, value in (count_src_ip_occurrence(src_ip).items()):
    values.append(value);
    keys.append(key);
    STATISTICS.append ({'node': key,
                        'number_of_sent_packets': value
                    })
maxIPSenders = find_max_ip_senders(keys, values);

for i in range (1, len(packets) + 1):
    if(frame_type[i] == "IEEE 802.3 LLC"):   
        PACKETS.append({'frame_number': frame_numbers[i], 
                        'len_frame_pcap': len_frame_pcap[i], 
                        'len_frame_medium': len_frame_medium[i],
                        'frame_type': frame_type[i],
                        'src_mac': src_mac[i], 
                        'dst_mac': dst_mac[i],
                        'sap': sap_type[i],
                        "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                        })
    elif(frame_type[i] == "IEEE 802.3 LLC & SNAP"):   
        PACKETS.append({'frame_number': frame_numbers[i], 
                        'len_frame_pcap': len_frame_pcap[i], 
                        'len_frame_medium': len_frame_medium[i],
                        'frame_type': frame_type[i],
                        'src_mac': src_mac[i], 
                        'dst_mac': dst_mac[i],
                        'pid': pid_type[i],
                        "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                        })                    
    elif(frame_type[i] == "Ethernet II"):   
        if(ether_type[i] == "IPv4"):
                if(protocol[i] == "TCP" or protocol[i] == "UDP"):
                    PACKETS.append({'frame_number': frame_numbers[i], 
                        'len_frame_pcap': len_frame_pcap[i], 
                        'len_frame_medium': len_frame_medium[i],
                        'frame_type': frame_type[i],
                        'src_mac': src_mac[i], 
                        'dst_mac': dst_mac[i],
                        'ether_type': ether_type[i],
                        'src_ip': src_ip[i], 
                        'dst_ip': dst_ip[i],
                        'protocol': protocol[i],
                        'src_port': src_port[i],
                        'dst_port': dst_port[i],
                        'app_protocol': app_protocol[i],
                        "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                        })                
                else:    
                    PACKETS.append({'frame_number': frame_numbers[i], 
                        'len_frame_pcap': len_frame_pcap[i], 
                        'len_frame_medium': len_frame_medium[i],
                        'frame_type': frame_type[i],
                        'src_mac': src_mac[i], 
                        'dst_mac': dst_mac[i],
                        'ether_type': ether_type[i],
                        'src_ip': src_ip[i], 
                        'dst_ip': dst_ip[i],
                        'protocol': protocol[i],
                        "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                        })
        elif(ether_type[i] == "ARP"):
                PACKETS.append({'frame_number': frame_numbers[i], 
                    'len_frame_pcap': len_frame_pcap[i], 
                    'len_frame_medium': len_frame_medium[i],
                    'frame_type': frame_type[i],
                    'src_mac': src_mac[i], 
                    'dst_mac': dst_mac[i],
                    'ether_type': ether_type[i],
                    "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                    })            
        else:
                PACKETS.append({'frame_number': frame_numbers[i], 
                    'len_frame_pcap': len_frame_pcap[i], 
                    'len_frame_medium': len_frame_medium[i],
                    'frame_type': frame_type[i],
                    'src_mac': src_mac[i], 
                    'dst_mac': dst_mac[i],
                    'ether_type': ether_type[i],
                    "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                    })                      
    else:
        PACKETS.append({
                        'frame_number': frame_numbers[i], 
                        'len_frame_pcap': len_frame_pcap[i], 
                        'len_frame_medium': len_frame_medium[i],
                        'frame_type': frame_type[i],
                        'src_mac': src_mac[i], 
                        'dst_mac': dst_mac[i], 
                        "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(yaml_hexa_frame[i])
                        })

# ===================================================
#   ADD TO DICTIONARY PACKETS_yaml[] WITH HEADER
# ===================================================

PACKETS_yaml.append({'name': name, 'pcap_name': pcap_name,'packets': PACKETS, "ipv4_senders": STATISTICS, "max_send_packets_by": maxIPSenders })

# ===================================================
#   SERIALIZE DICTIONARY PACKETS_yaml[] TO .yaml
# ===================================================

yaml = ruamel.yaml.YAML()
yaml.sort_keys = False
yaml.explicit_start = False
yaml.default_flow_style=False

with open(file_name, 'w') as f:
    yaml.dump_all(PACKETS_yaml, f)

# ===================================================