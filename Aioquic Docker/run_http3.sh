# Set the SSL key log file
export SSLKEYLOGFILE="$(pwd)/sslkeys-demo.log"
echo "SSLKEYLOGFILE is set to: $SSLKEYLOGFILE"
# Run the HTTP/3 server in the background
nohup python3 examples/http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem > server.log 2>&1 &

# Wait a bit to ensure the server is up and running
sleep 5

# Run the HTTP/3 client
python3 examples/http3_client.py --ca-certs tests/pycacert.pem https://localhost:4433/ > client.log 2>&1

# Print message to indicate the script has finished running
echo "Server and client have been executed. Check server.log and client.log for details."
