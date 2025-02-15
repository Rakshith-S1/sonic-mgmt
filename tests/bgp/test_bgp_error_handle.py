"""Check for BGP error handling"""

import logging
import pytest
import socket
import time
import tempfile
import contextlib
from scapy.all import sniff, rdpcap, IP
from scapy.contrib import bgp

from tests.common.utilities import wait_until
from tests.common.helpers.bgp import BGPNeighbor
from tests.bgp.bgp_helpers import capture_bgp_packages_to_file, is_tcpdump_running, fetch_and_delete_pcap_file

# Configuration Constants
PTF_INTERFACE = "eth2"
PTF_IP = "192.168.0.2"
SUBNET_MASK = "21"
DUT_IP = "192.168.0.1"
NEIGHBOR_ASN = 65001
DUT_ASN = 65100
BGP_PORT = 179
MALFORMED_BGP_PACKET = b"\xff" * 19 + b"\x00"  # Invalid BGP packet
WAIT_TIMEOUT = 60


@pytest.fixture
def setup_ptf_interface(ptfhost):
    """Fixture to set up and tear down the PTF BGP neighbor"""

    # Configure IP on PTF eth1
    logging.info(f"Assigning IP {PTF_IP}/{SUBNET_MASK} to {PTF_INTERFACE} on PTF")
    ptfhost.shell(f"ip addr add {PTF_IP}/{SUBNET_MASK} dev {PTF_INTERFACE}")
    ptfhost.shell(f"ip link set {PTF_INTERFACE} up")
    yield
    logging.info("Tearing down IP from PTF")
    ptfhost.shell(f"ip addr del {PTF_IP}/{SUBNET_MASK} dev {PTF_INTERFACE}")
    ptfhost.shell(f"ip link set {PTF_INTERFACE} down")

@pytest.fixture
def setup_dut_bgp(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Fixture to set up and tear down the DUT config for ptf bgp neighbor"""

    # Configure BGP neighbor on DUT
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bgp_config_cmds = f"vtysh -c \"configure terminal\" \
            -c \"router bgp {DUT_ASN}\" \
            -c \"neighbor {PTF_IP} remote-as {NEIGHBOR_ASN}\" \
            -c \"neighbor {PTF_IP} peer-group PEER_V4\" \
            -c \"neighbor {PTF_IP} description PTF\" \
            -c \"neighbor {PTF_IP} timers 3 10\" \
            -c \"neighbor {PTF_IP} timers connect 10\" \
            -c \"address-family ipv4 unicast\" \
            -c \"neighbor {PTF_IP} activate\""
    logging.info(f"Configure DUT BGP for neighbor {PTF_IP} asn {NEIGHBOR_ASN}")
    duthost.shell(bgp_config_cmds)
    yield
    logging.info("Tear down BGP neighbor")
    duthost.shell(f"vtysh -c \"configure terminal\" \
            -c \"router bgp {DUT_ASN}\" \
            -c \"no neighbor {PTF_IP} remote-as {NEIGHBOR_ASN}\"")

def send_bgp_packet(ptfhost, target_ip, target_port, messages):
    """Send a malformed BGP packet to DUT using socket programming."""

    temp_script_path = '/tmp/send_bgp_socket.py'
    try:
        script_content = f"""
import socket
import logging
import time
def send_bgp_message():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('{target_ip}', {target_port}))

        bgp_messages = {messages}
        for message in bgp_messages:
            sock.sendall(message)
            time.sleep(1)

        time.sleep(20)
    finally:
        sock.close()
    #except Exception as e:
    #    logging.error(f'Unexpected error')
send_bgp_message()
"""
        ptfhost.shell(f"echo \"{script_content}\" > {temp_script_path}")
        logging.info(f"Sending BGP message to {target_ip} port {target_port}")
        ptfhost.shell(f"python3 {temp_script_path}")
        logging.info(f"BGP message sent to {target_ip}:{target_port}")
    except Exception as e:
        logging.error(f"Failed to send malformed BGP packet: {e}")

@contextlib.contextmanager
def capture_bgp_packets(duthost, iface, pcap_file):
    """Capture tcpdump and kill the process"""
    logging.info("Start tcpdump on DUT to capture BGP packets")
    start_pcap = f"tcpdump -i {iface} port 179 -w {pcap_file}"
    tcpstartcmd = f"tcpdump -i {iface} port 179 -w {pcap_file} &"
    tcpstopcmd = f"sudo pkill -f 'tcpdump -i {iface}'"
    duthost.file(path=pcap_file, state="absent")
    duthost.shell(tcpstartcmd)
    time.sleep(2)

    try:
        yield
    finally:
        logging.info("Wait 10 seconds and Stop tcpdump on DUT")
        time.sleep(10)
        duthost.shell(tcpstopcmd, module_ignore_errors=True)


def is_bgp_error_logged(duthost, neighbor_ip):
    """Check if BGP error messages are logged on the DUT."""
    error_log_cmd = f"grep 'BGP Error' /var/log/syslog | grep {neighbor_ip}"
    log_output = duthost.shell(error_log_cmd, module_ignore_errors=True)['stdout']
    return "BGP Error" in log_output

def extract_error_codes(pcap_file):
    """Reads pcap file and extracts BGP Notification error codes."""
    packets = rdpcap(pcap_file)
    error_list = []
    logging.info("Extract Notification message error codes and subcodes")
    for pkt in packets:
        if IP in pkt and bgp.BGPNotification in pkt:
            error_code = pkt[bgp.BGPNotification].error_code
            error_subcode = pkt[bgp.BGPNotification].error_subcode
            error_list.append((error_code, error_subcode))
        #else:
            #pytest.fail("No Notification packets captured in PCAP")
    return error_list

def test_bgp_open_message_no_neighbor(setup_ptf_interface, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, request):
    """Test BGP error handling without BGP neighbor configured, should return OPEN Message Error (2), subcode Bad Peer AS (2)"""

    iface = "Vlan1000"
    pcap_file = "/tmp/bgp_messages.pcap"
    expected_error = (2, 2) # OPEN Message Error (2), subcode Bad Peer AS (2)
    log_dir = "/tmp"

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    
    bgp_open_message = (
        b"\xff" * 16 + # 16 byte marker
        struct.pack("!H", 29) +  # Message Length: 29 bytes
        b"\x01" +  # Type: OPEN
        b"\x04" +  # Version: 4
        struct.pack("!H", NEIGHBOR_ASN) + 
        b"\x00\x5a" +  # Hold Time
        socket.inet_aton(PTF_IP) + b"\x00"  # BGP Identifier + Optional Params
    )
    
    with capture_bgp_packets(duthost, iface, pcap_file):
        send_bgp_packet(ptfhost, DUT_IP, BGP_PORT, [bgp_open_message])

    local_pcap_filename = fetch_and_delete_pcap_file(pcap_file, log_dir, duthost, request)
    
    errors = extract_error_codes(local_pcap_filename)
    logging.info(f"Extracted error codes = {errors}")
    logging.info(f"Expected error code = {expected_error}")

    assert expected_error in errors, f"Expected BGP error {expected_error} - OPEN Message Error (2), subcode Bad Peer AS (2) not found in PCAP"


def test_bgp_update_message(setup_ptf_interface, setup_dut_bgp, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, request):
    """Test BGP error handling with BGP neighbor configured, should return UPDATE Message Error (3) Malformed Attribute List (1)"""

    iface = "Vlan1000"
    pcap_file = "/tmp/bgp_messages.pcap"
    expected_error = (3, 1) # OPEN Message Error (2), subcode Bad Peer AS (2)
    log_dir = "/tmp"

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    bgp_open_message = (
        b"\xff" * 16 + # 16 byte marker
        struct.pack("!H", 29) +  # Message Length: 29 bytes
        b"\x01" +  # Type: OPEN
        b"\x04" +  # Version: 4
        struct.pack("!H", NEIGHBOR_ASN) +
        b"\x00\x5a" +  # Hold Time
        socket.inet_aton(PTF_IP) + b"\x00"  # BGP Identifier + Optional Params
    )

    bgp_keepalive_message = b"\xff" * 16 + struct.pack("!H", 19) + b"\x04"

    set_origin = b"\x40\x01\x01\x00"  # Origin attribute (IGP)
    set_aspath = b"\x40\x02\x06\x02\x01\x00\x00"  # AS_PATH attribute
    NEXT_HOP = "192.168.0.2"
    set_nexthop = socket.inet_aton(NEXT_HOP) # NEXT_HOP

    path_attr_len = len(set_origin) + len(set_nexthop) + len(set_aspath)

    bgp_update_message = (
        b"\xff" * 16 +  # Marker (16 bytes)
        struct.pack("!H", 23 + path_attr_len) +  # Total Length (header + withdrawn routes + attributes)
        b"\x02" +  # Type (UPDATE)
        b"\x00\x00" +  # Withdrawn Routes Length (0)
        struct.pack("!H", path_attr_len) +  # Path Attributes Length
        set_origin  + # Origin [IGP]
        set_nexthop + # Next Hop
        set_aspath # Path Attributes
    )

    with capture_bgp_packets(duthost, iface, pcap_file):
        send_bgp_packet(ptfhost, DUT_IP, BGP_PORT, [bgp_open_message, bgp_keepalive_message, bgp_update_message])

    local_pcap_filename = fetch_and_delete_pcap_file(pcap_file, log_dir, duthost, request)

    errors = extract_error_codes(local_pcap_filename)
    logging.info(f"Extracted error codes = {errors}")
    logging.info(f"Expected error code = {expected_error}")

    assert expected_error in errors, f"Expected BGP error {expected_error} - UPDATE Message Error (3) Malformed Attribute List (1) not found in PCAP"
