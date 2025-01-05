for i in {29..35}
do
    ip addr add 192.168.40.$i/24 dev enp0s3
done
