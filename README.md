# HTTP/3 Security Research Project

A comprehensive security research project investigating HTTP/3 (QUIC protocol) vulnerabilities through practical attack implementations. This repository demonstrates various attack vectors against HTTP/3 connections using Dockerized environments with Aioquic and QUICforge frameworks.

## 🎯 About This Project

This project explores critical security vulnerabilities in the HTTP/3 protocol (QUIC) through hands-on demonstrations of:

- **Spoofed ACK Attacks**: Request forgery by manipulating QUIC acknowledgment frames to force unnecessary retransmissions
- **0-RTT Replay Attacks**: Exploiting early data transmission in QUIC's zero round-trip time feature ($$)
- **HTTP/3 Flood/Slowloris**: Denial of service demonstrations targeting HTTP/3 connections ($$)

The project uses containerized environments to safely demonstrate these attacks in an isolated, controlled setting.

## 📋 Technologies Used

- **[Aioquic](https://github.com/aiortc/aioquic)**: Python implementation of QUIC (RFC 9000) and HTTP/3 (RFC 9114)
- **QUICforge**: QUIC packet manipulation and forgery framework
- **Docker**: Containerized isolation for server, client, and attacker environments
- **Scapy**: Low-level packet crafting and manipulation
- **Wireshark**: Network traffic analysis and visualization

## 📁 Project Structure

```
.
├── Aioquic Docker/              # HTTP/3 server environment
├── Aioquic Client Docker/       # HTTP/3 client implementation
├── QUICforge Docker/            # Attack framework container
│   └── QUICforge/
│       ├── request_forgery.py   # Main attack orchestration script
│       ├── Spoofed_Ack_First_Phase.py
│       ├── Spoofed_Ack_Second_Phase.py
│       ├── Spoofed_Ack_Third_Phase.py
│       └── Spoofed_Ack_Forth_Phase.py
├── Curl Docker/                 # Alternative client using curl
├── Attacks Keys/                # Generated TLS secrets and logs
│   ├── ssl_0-RTT.log
│   ├── ssl_Spoofed_ACK_Attack.log
│   └── ...
├── Qlog Attacks/                # QLOG files for attack analysis
│   ├── client/                  # Client-side QLOG traces
│   │   ├── ack_attack_client.qlog
│   │   └── ...
│   └── attacker/                # Attacker-side QLOG traces
│       ├── ack_attack_forge.qlog
│       └── ...
├── Wireshark attacks/           # Captured attack traffic (PCAP)
│   ├── 0-RTT-Connection.pcapng
│   ├── HTTP3-Flood.pcapng
│   ├── Spoofed_ACK_Attack.pcapng
│   └── ...
├── Makefile                     # Container management automation
├── .gitignore                   # Git ignore rules
└── README.md
```

## ⚡ Prerequisites

Before starting, ensure you have the following installed:

- **Docker** (v20.10+): For running isolated containerized environments
- **Make**: For simplified container management and command execution
- **Python 3.8+**: Required for local development and testing
- **OpenSSL**: For generating SSL/TLS certificates
- **Wireshark** (Optional): For analyzing captured attack traffic in `.pcapng` files

### System Requirements

- Linux-based OS (tested on Ubuntu 20.04+)
- Minimum 4GB RAM
- 10GB free disk space
- Root/sudo access for network manipulation capabilities

## 🚀 Installation & Setup

Follow these steps to set up the complete environment:

### 1. Clone the Repository

```bash
git clone https://github.com/Eladi24/HTTP-3.0-Final-Project.git
cd HTTP-3.0-Final-Project
```

### 2. Generate SSL/TLS Certificates

Generate the required certificates for secure QUIC connections:

```bash
# Generate server certificate
openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout ssl_key.pem \
  -out ssl_cert.pem \
  -days 365 \
  -subj "/CN=localhost"
```

**Note**: The generated `ssl_cert.pem` and `ssl_key.pem` files should remain in the project root directory.

### 3. Build Docker Images

Build the Docker images for each component:

**Build Aioquic Server:**

```bash
cd "Aioquic Docker"
docker build -t aioquic-docker .
cd ..
```

**Build QUICforge (Attacker):**

```bash
cd "QUICforge Docker"
docker build -t quicforge .
cd ..
```

**Build Client:**

```bash
cd "Aioquic Client Docker"
docker build -t client-docker .
cd ..
```

### 4. Initialize Containers

Create and start the containers for the first time:

**Start Aioquic Server:**

```bash
docker run -dit --name aioquic-container -p 4433:4433 aioquic-docker
```

**Start Client:**

```bash
docker run -dit --name client-container -p 1234:4433 -v shared-data:/app/shared client-docker
```

**Start QUICforge (Attacker):**

```bash
docker run --cap-add=NET_ADMIN \
           --cap-add=NET_RAW \
           --network=host \
           -dit \
           --name quicforge-container \
           -v shared-data:/app/shared \
           -v "$(pwd)/ssl_cert.pem:/mnt/certs/ssl_cert.pem" \
           -v "$(pwd)/ssl_key.pem:/mnt/keys/ssl_key.pem" \
           quicforge
```

**Important**: The attacker container requires `NET_ADMIN` and `NET_RAW` capabilities to perform network-level packet manipulation.

## 💻 Usage

After initial setup, use the Makefile commands to manage and interact with the containers.

### Accessing Container Shells

Open interactive shells inside running containers:

- **Access Aioquic Server:**
  ```bash
  make execAioquic
  ```

- **Access Client:**
  ```bash
  make execClient
  ```

- **Access QUICforge (Attacker):**
  ```bash
  make execQuicforge
  ```

### 🎯 Executing Attacks

#### Spoofed ACK Attack

This attack manipulates QUIC acknowledgment frames to create artificial packet loss, forcing the server to waste resources on unnecessary retransmissions.

**Step 1: Start the Client Connection**

```bash
make execClient
python3 minimal_http_client.py https://<server_ip>:<target_ip>/
```

Replace `<server_ip>` with your server's IP address (e.g., `172.17.0.2`).

**Step 2: Launch the Attack**

In a separate terminal:

```bash
make execQuicforge
cd QUICforge
python3 request_forgery.py ack <victim_ip> <target_ip> \
  --victim_port 4433 \
  --target_port <target_port>
```

**Example:**

```bash
python3 request_forgery.py ack 172.17.0.2 172.17.0.3 \
  --victim_port 4433 \
  --target_port 4433
```

**What Happens:**
- The attack intercepts ACK frames from the client
- Modifies them to report fake packet losses (gaps of 500, 1500, 2500 packets)
- Server responds by retransmitting "lost" packets and sending PING probes
- Results in ~4x increase in network traffic and wasted server resources

### 🔧 Container Management

Use these Makefile commands to manage container lifecycle:

- **Start Containers:**
  ```bash
  make startContainers
  ```

- **Stop Containers:**
  ```bash
  make stopContainers
  ```

- **Restart Containers:**
  ```bash
  make restartContainers
  ```

- **Check Container Status:**
  ```bash
  make containersStatus
  ```

### 📊 Monitoring & Logging

- **View Server Logs (Live):**
  ```bash
  make logAioquic
  ```

- **Extract TLS Secrets from Attacker:**
  ```bash
  make copyAttackerLog
  ```
  This copies `client_secrets.log` to your local directory as `ssl_attacker.log`.

## 🔬 Analyzing Attack Traffic

### Using Wireshark

The `Wireshark attacks/` directory contains pre-captured PCAP files demonstrating each attack type.

**To analyze:**

```bash
wireshark "Wireshark attacks/Spoofed_ACK_Attack.pcapng"
```

**Configure Wireshark for QUIC Decryption:**

1. Go to **Edit > Preferences > Protocols > TLS**
2. Set **(Pre)-Master-Secret log filename** to point to your `client_secrets.log`
3. Enable **Reassemble TLS records spanning multiple TCP segments**

**Key Fields to Examine:**

- QUIC packet numbers and ACK frames
- Retransmission indicators
- Connection IDs and migration events
- CRYPTO frame contents

### Understanding Attack Success Indicators

**For Spoofed ACK Attack:**
- Look for "Loss detection triggered" in server logs
- Multiple "Sending PING (probe)" messages
- "Scheduled CRYPTO data for retransmission" entries
- Increased packet count (~4x normal traffic)
- Server-initiated connection termination

## 🛠️ Troubleshooting

### Container Won't Start

**Problem**: Port already in use
```bash
# Check if ports are occupied
sudo netstat -tulpn | grep -E '4433|1234'

# Kill processes using those ports if needed
sudo kill -9 <PID>
```

### Permission Denied Errors

**Problem**: Insufficient privileges for QUICforge
```bash
# Ensure the container has required capabilities
docker inspect quicforge-container | grep -A 10 CapAdd
```

**Solution**: Rebuild the container with proper capabilities (see Step 4 above).

### Certificate Errors

**Problem**: Expired or missing certificates
```bash
# Check certificate validity
openssl x509 -in ssl_cert.pem -text -noout | grep "Not After"

# Regenerate if expired
openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout ssl_key.pem \
  -out ssl_cert.pem \
  -days 365 \
  -subj "/CN=localhost"
```

### Packet Decryption Failed

**Problem**: Wireshark shows "Payload decryption failed"

**Solution**:
1. Ensure TLS secrets log file path is correctly set in Wireshark
2. Verify the log file contains the correct session secrets
3. Capture traffic from the beginning of the connection (including Initial packets)

### Attack Not Working

**Problem**: Server doesn't show retransmission behavior

**Checklist**:
- Verify iptables rules are correctly inserted
- Check that TLS secrets are being extracted
- Ensure packet modification is occurring (check debug output)
- Verify connection uses QUIC v2 (not v1)

## 📚 Attack Development Phases

The `QUICforge Docker/QUICforge/` directory contains the evolutionary development of the Spoofed ACK attack:

1. **`Spoofed_Ack_First_Phase.py`**: Basic packet interception and decryption
2. **`Spoofed_Ack_Second_Phase.py`**: ACK frame parsing and modification
3. **`Spoofed_Ack_Third_Phase.py`**: Re-encryption with authentication handling
4. **`Spoofed_Ack_Forth_Phase.py`**: Final optimized version with multiple fallback strategies
5. **`request_forgery.py`**: Complete attack orchestration with all attack types

These phases demonstrate the iterative process of developing a working QUIC packet manipulation attack against authenticated encryption.

## ⚠️ Legal Disclaimer

**This project is intended exclusively for educational and research purposes.**

- Only use these tools in **controlled laboratory environments**
- You must have **explicit permission** to test these attacks on any system
- Unauthorized use against systems you don't own is **illegal** and unethical
- The authors assume **no responsibility** for misuse of this code

This research aims to improve understanding of HTTP/3 security vulnerabilities to help develop better defenses.

## 🔗 References & Resources

- [RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9001 - Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)
- [Aioquic Documentation](https://github.com/aiortc/aioquic)
- [QUIC Working Group](https://quicwg.org/)

## 👥 Authors

Elad Imany and Orel Shalem

## 📄 License
?

## 🤝 Contributing

Contributions to improve attack techniques, add new vulnerabilities, or enhance documentation are welcome. Please open an issue or submit a pull request.

---

**For questions or issues, please open a GitHub issue or contact the maintainers.**
