import socket
import logging
def send_bgp_message():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect("192.168.0.1", "179")
        sock.close()
        logging.info(f"Sent malformed BGP packet to {target_ip}:{target_port}")
    except Exception as e:
        logging.error("Unexpected error")

send_bgp_message()
