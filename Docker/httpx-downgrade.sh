#!/bin/bash

# Define the URL parameter within the script
URL="https://caddyserver.com/"

# Set the path for the SSL key log file in the current directory
SCRIPT_DIR="$(pwd)"
SSLKEYLOGFILE="$SCRIPT_DIR/sslkeys-downgrade.log"
export SSLKEYLOGFILE

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed."
    exit 1
fi

# Notify the user about the location of the SSL key log file
echo "[*] SSL key log file will be saved at: $SSLKEYLOGFILE"

# Function to test HTTP/1.1 connectivity
test_http1() {
    local url=$1
    echo "[*] Testing HTTP/1.1 connectivity to $url..."
    curl --http1.1 -v -s -o /dev/null -w "HTTP/1.1 Response Code: %{http_code}\n" "$url" 2>&1 | grep -E "ALPN|http_code"
    if [ $? -eq 0 ]; then
        echo "[+] HTTP/1.1 request succeeded."
    else
        echo "[-] HTTP/1.1 request failed."
    fi
}

# Function to test HTTP/2 connectivity
test_http2() {
    local url=$1
    echo "[*] Testing HTTP/2 connectivity to $url..."
    curl --http2 -v -s -o /dev/null -w "HTTP/2 Response Code: %{http_code}\n" "$url" 2>&1 | grep -E "ALPN|http_code"
    if [ $? -eq 0 ]; then
        echo "[+] HTTP/2 request succeeded."
    else
        echo "[-] HTTP/2 request failed."
    fi
}

# Function to test HTTP/3 connectivity
test_http3() {
    local url=$1
    echo "[*] Testing HTTP/3 connectivity to $url..."
    
    # Capture detailed ALPN negotiation
    local output
    output=$(curl --http3 -v -s -o /dev/null "$url" 2>&1)
    echo "$output" | grep -i "ALPN"

    # Extract and display the protocols requested by the client and selected by the server
    local client_alpn
    local server_alpn
    client_alpn=$(echo "$output" | grep -i "ALPN, offering" | awk -F ': ' '{print $2}')
    server_alpn=$(echo "$output" | grep -i "ALPN, server accepted" | awk -F ': ' '{print $2}')
    
    echo "  [ALPN] Client offered protocols: $client_alpn"
    echo "  [ALPN] Server selected protocol: $server_alpn"

    # Check if the curl command succeeded
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "[+] HTTP/3 request succeeded."
    else
        echo "[-] HTTP/3 request failed."
    fi
}

# Function to verify if SSL key log file was created
verify_sslkeylogfile() {
    if [ -f "$SSLKEYLOGFILE" ]; then
        echo "[+] SSL key log file successfully created at: $SSLKEYLOGFILE"
    else
        echo "[-] Failed to create SSL key log file."
    fi
}

# Run the tests
echo "Testing HTTP downgrade on $URL..."
test_http3 "$URL"
test_http2 "$URL"
test_http1 "$URL"

# Verify SSL key log file creation
verify_sslkeylogfile
