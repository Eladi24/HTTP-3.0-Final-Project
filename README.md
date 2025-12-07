# HTTP 3.0 Final Project

A comprehensive project investigating HTTP/3 security vulnerabilities and performance, built using Aioquic and QUICforge environments. This repository contains Dockerized setups for an Aioquic server, a custom client, and the QUICforge attack framework.

## Prerequisites

- **Docker**: Essential for running the isolated environments (Server, Client, Attacker).
- **Make**: Used for executing commands inside running containers and managing their state.
- **Python3**: Required for local script execution and development.
- **Wireshark**: (Optional) For analyzing the provided `.pcapng` capture files.

## Installation / Setup

Follow these steps in order to set up the environment. You must build the images and run the containers once before you can use the Makefile to manage them.

### 1. Clone the Repository

```bash
git clone [https://github.com/Eladi24/HTTP-3.0-Final-Project.git](https://github.com/Eladi24/HTTP-3.0-Final-Project.git)
cd http-3.0-final-project
````

### 2\. Generate Certificates

Generate the SSL certificates required for the server and attacker.

```bash
openssl req -x509 -nodes -newkey rsa:4096 -keyout <name>.key -out <name>.pem -days 365
```

### 3\. Build Docker Images

Build the specific Docker images for the server, client, and attacker environments.

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

### 4\. Run Containers (Initialization)

Once the images are built, use `docker run` to create and start the containers. This step is required to initialize the environments.

**Run Aioquic Server:**

```bash
docker run -dit --name aioquic-container -p 4433:4433 aioquic-docker
```

**Run Client:**

```bash
docker run -dit --name client-container -p 1234:4433 -v shared-data:/app/shared client-docker
```

**Run QUICforge (Attacker):**
*Note: This container requires admin privileges (`NET_ADMIN`) to perform network attacks.*

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

## Usage

After the containers have been created (via `docker run`), you can use the provided `Makefile` to execute commands inside them and manage their lifecycle (start/stop/restart).

### Accessing Components (Executing)

Use these commands to open an interactive shell inside the running containers:

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

### Running Attacks

To initiate an attack, follow this sequence:

1.  **Start Client Session:**
    Access the client container and attempt to connect to the server.

    ```bash
    make execClient
    python3 minimal_http_client.py https://<server_ip>:<server_port>/
    ```

    *(Replace `<server_ip>` and `<server_port>` with the actual IP and port, e.g., `172.18.0.2:4433`)*.

    Once the command runs, type `exit` to leave the client container.

2.  **Launch Attack:**
    Access the attacker container and run the forgery script.

    ```bash
    make execQuicforge
    cd QUICForge
    python3 request_forgery.py ack <victim_ip> <target_ip> --victim_port <victim_port> --target_port <target_port>
    ```

    *(Replace placeholders with specific IPs and ports)*

    **Example:**

    ```bash
    python3 request_forgery.py ack 172.17.0.2 123.123.123.123 --victim_port 4433 --target_port 12345
    ```

### Managing Containers

Use these make commands to manage the lifecycle of the containers you created in the "Setup" phase:

  - **Start Environments:** (Resumes stopped containers)

    ```bash
    make startContainers
    ```

  - **Stop Environments:** (Stops running containers and cleans up keys)

    ```bash
    make stopContainers
    ```

  - **Restart Environments:**

    ```bash
    make restartContainers
    ```

  - **Check Status:**

    ```bash
    make containersStatus
    ```

### Logging

  - **View Server Logs:**
    Displays the live logs from the Aioquic server.

    ```bash
    make logAioquic
    ```

  - **Extract Attacker Secrets:**
    Copies the `client_secrets.log` from the attacker container to your local machine as `ssl_attacker.log`.

    ```bash
    make copyAttackerLog
    ```

## Project Structure

  - **Aioquic Docker/**: Server implementation based on Aioquic.
  - **Aioquic Client Docker/**: Client implementation and minimal HTTP client scripts.
  - **QUICforge Docker/**: Containerized QUICforge attack tool.
      - **`request_forgery.py`**: The primary attack script.
      - **Attack Development Phases**: This folder also contains the evolutionary steps of the Spoofed ACK attack script:
          - `Spoofed_Ack_First_Phase.py`
          - `Spoofed_Ack_Second_Phase.py`
          - `Spoofed_Ack_Third_Phase.py`
          - `Spoofed_Ack_Forth_Phase.py`
  - **Curl Docker/**: Implementation using Curl for HTTP/3 interactions.
  - **Attacks Keys/**: Logs and keys generated during specific attack scenarios (e.g., `ssl_0-RTT.log`, `ssl_Spoofed_ACK_Attack.log`).
  - **Wireshark attacks/**: PCAP files of attack traffic (e.g., `0-RTT-Connection.pcapng`, `HTTP3-Flood.pcapng`).
