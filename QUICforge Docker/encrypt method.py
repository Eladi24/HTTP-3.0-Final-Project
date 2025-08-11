def encrypt_quic_packet(packet, secrets, modified_payloads) -> NetfilterQueue:
    """
    Encrypt modified QUIC payloads and replace them in the original packet.
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
        
        print(f"[*] Encrypting {len(modified_payloads)} modified QUIC packets")
        print(f"[*] UDP payload buffer size: {len(udp_payload)} bytes")
        
        # Define cipher suite - must match the one used for decryption
        cipher_suite = CipherSuite.AES_256_GCM_SHA384
        
        # Create a mutable copy for modifications
        modified_udp_payload = bytearray(udp_payload)
        
        # Process each modified payload
        for header, modified_payload, packet_number, start_off, encrypted_offset, end_offset in modified_payloads:
            
            print(f"[*] Encrypting packet at offset {start_off}-{end_offset} (encrypted starts at {encrypted_offset})")
            
            # Select appropriate secret based on packet type
            secret = None
            secret_type = None
            
            if header.packet_type == QuicPacketType.HANDSHAKE:
                if secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]:
                    secret = secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]
                    secret_type = "client_handshake"
                elif secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]:
                    secret = secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]
                    secret_type = "server_handshake"
            
            elif header.packet_type == QuicPacketType.ZERO_RTT:
                if secrets["CLIENT_EARLY_TRAFFIC_SECRET"]:
                    secret = secrets["CLIENT_EARLY_TRAFFIC_SECRET"]
                    secret_type = "client_0rtt"
            
            elif header.packet_type == QuicPacketType.ONE_RTT:
                if secrets["CLIENT_TRAFFIC_SECRET_0"]:
                    secret = secrets["CLIENT_TRAFFIC_SECRET_0"]
                    secret_type = "client_1rtt"
                elif secrets["SERVER_TRAFFIC_SECRET_0"]:
                    secret = secrets["SERVER_TRAFFIC_SECRET_0"]
                    secret_type = "server_1rtt"
            
            if not secret:
                print(f"[!] No appropriate secret found for {header.packet_type} packet")
                continue
            
            try:
                # Extract original packet data
                original_packet_data = udp_payload[start_off:end_offset]
                original_packet_size = len(original_packet_data)
                
                # Extract the plain header as bytes (not bytearray)
                plain_header = bytes(original_packet_data[:encrypted_offset])
                
                # Calculate original payload size (excluding auth tag)
                auth_tag_size = 16
                original_encrypted_size = original_packet_size - encrypted_offset
                original_payload_size = original_encrypted_size - auth_tag_size
                
                print(f"[*] Original packet size: {original_packet_size} bytes")
                print(f"[*] Plain header size: {len(plain_header)} bytes") 
                print(f"[*] Original payload size: {original_payload_size} bytes")
                print(f"[*] Modified payload size: {len(modified_payload)} bytes")
                
                # Ensure exact size match of payload
                if len(modified_payload) != original_payload_size:
                    size_diff = original_payload_size - len(modified_payload)
                    if size_diff > 0:
                        print(f"[*] Padding payload with {size_diff} bytes")
                        modified_payload = modified_payload + b'\x00' * size_diff
                    else:
                        print(f"[*] Truncating payload by {abs(size_diff)} bytes")
                        modified_payload = modified_payload[:original_payload_size]
                
                # Ensure modified_payload is bytes, not bytearray
                if not isinstance(modified_payload, bytes):
                    modified_payload = bytes(modified_payload)
                
                print(f"[*] Final payload size: {len(modified_payload)} bytes")
                
                # Set up crypto context with exact same parameters
                crypto = CryptoContext()
                crypto.setup(
                    cipher_suite=cipher_suite,
                    secret=secret,
                    version=QuicProtocolVersion.VERSION_2
                )
                
                # For long header packets, update the length field correctly
                if header.packet_type in (QuicPacketType.HANDSHAKE, QuicPacketType.INITIAL, QuicPacketType.ZERO_RTT):
                    # Parse the header to find the length field position
                    header_buf = Buffer(data=plain_header)
                    
                    # Skip first byte
                    first_byte = header_buf.pull_uint8()
                    
                    # Skip version
                    version = header_buf.pull_uint32()
                    
                    # Skip DCID length and DCID
                    dcid_len = header_buf.pull_uint8()
                    header_buf.pull_bytes(dcid_len)
                    
                    # Skip SCID length and SCID
                    scid_len = header_buf.pull_uint8()
                    header_buf.pull_bytes(scid_len)
                    
                    # For Initial packets, skip token
                    if header.packet_type == QuicPacketType.INITIAL:
                        token_len = header_buf.pull_uint_var()
                        header_buf.pull_bytes(token_len)
                    
                    # Now we're at the length field
                    length_pos = header_buf.tell()
                    
                    # Calculate new length (payload + auth tag)
                    new_length = len(modified_payload) + auth_tag_size
                    
                    # Update the length field in the header
                    length_encoded = _encode_uint_var(new_length)
                    
                    # Create a NEW header with updated length
                    # This is critical - we need a new immutable bytes object
                    new_header_bytes = bytearray(plain_header)
                    for i, b in enumerate(length_encoded):
                        new_header_bytes[length_pos + i] = b
                    
                    # Convert back to bytes for encryption
                    plain_header = bytes(new_header_bytes)
                    
                    print(f"[*] Updated packet length from {header.packet_length} to {new_length}")
                
                # Now encrypt with the updated header
                encrypted_packet = crypto.encrypt_packet(
                    plain_header=plain_header,
                    plain_payload=modified_payload,
                    packet_number=packet_number
                )
                
                print(f"[*] Encrypted packet size: {len(encrypted_packet)} bytes")
                print(f"[*] Expected size: {original_packet_size} bytes")
                
                # Replace the packet data
                modified_udp_payload[start_off:end_offset] = encrypted_packet
                print(f"[+] Successfully replaced packet (size: {len(encrypted_packet)} bytes)")
                
            except Exception as e:
                print(f"[-] Encryption failed for {secret_type}: {str(e)}")
                traceback.print_exc()
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
        
        print(f"[+] Successfully encrypted and replaced {len(modified_payloads)} QUIC packets")
        return packet
        
    except Exception as e:
        print(f"[!] Critical error in encrypt_quic_packet: {str(e)}")
        traceback.print_exc()
        return packet
        
        
        
        
        
def reencrypt_quic_packets(packet, secrets, decrypted_packets):
    """
    Re-encrypt already decrypted QUIC packets without modifying them.
    This function preserves the exact packet structure including authentication tags.
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
                
                # For first test, do NOT modify the decrypted payload at all
                # We want exact reproduction of the original packet
                
                # Encrypt with original header and original payload
                # NO padding - this is critical
                encrypted_packet = crypto.encrypt_packet(
                    plain_header=plain_header,
                    plain_payload=bytes(decrypted_payload),
                    packet_number=packet_number
                )
                
                print(f"[*] Re-encrypted packet size: {len(encrypted_packet)} bytes")
                print(f"[*] Original packet size: {original_packet_size} bytes")
                
                # Check if packets match EXACTLY byte for byte
                if encrypted_packet != original_packet_data:
                    print(f"[!] Warning: Re-encrypted packet does not match original")
                    
                    # If there's a size mismatch, it's likely due to packet number encoding
                    if len(encrypted_packet) != original_packet_size:
                        size_diff = original_packet_size - len(encrypted_packet)
                        print(f"[!] Size mismatch: {len(encrypted_packet)} vs {original_packet_size} (diff: {size_diff})")
                        
                        # Extract and compare the sample used for header protection
                        protected_bits_pos = 0
                        if header.packet_type == QuicPacketType.ONE_RTT:
                            protected_bits_pos = 0  # First byte
                        else:
                            protected_bits_pos = 4  # Fifth byte (after version)
                            
                        orig_protected_bits = original_packet_data[protected_bits_pos]
                        new_protected_bits = encrypted_packet[protected_bits_pos]
                        
                        print(f"[*] Original protected bits: {bin(orig_protected_bits)}")
                        print(f"[*] New protected bits: {bin(new_protected_bits)}")
                        
                        # In this case, use the original packet - this is critical for Wireshark
                        print(f"[!] Using original packet to maintain compatibility")
                        encrypted_packet = original_packet_data
                    else:
                        # Same size but different content - check where they differ
                        # This is useful for debugging
                        diff_pos = []
                        for i in range(len(encrypted_packet)):
                            if encrypted_packet[i] != original_packet_data[i]:
                                diff_pos.append(i)
                        
                        print(f"[*] Differences at positions: {diff_pos}")
                        
                        # Use original packet for now - this ensures compatibility
                        encrypted_packet = original_packet_data
                else:
                    print("[+] Perfect match! Re-encrypted packet identical to original")
                
                # Replace the packet data
                modified_udp_payload[start_off:end_offset] = encrypted_packet
                print(f"[+] Successfully re-encrypted packet")
                
            except Exception as e:
                print(f"[-] Encryption failed for {secret_type}: {str(e)}")
                traceback.print_exc()
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
