# update and install requirements
sudo apt-get update
sudo apt-get install bind9 bind9utils

# create directories
sudo mkdir -p /etc/bind

# create files
# contents in runcont.txt
sudo nano /etc/bind/named.conf.options
sudo nano /etc/bind/named.conf.local
sudo nano /etc/bind/db.resolverinfo

# set permissions
sudo chown -R bind:bind /etc/bind
sudo chmod 644 /etc/bind/db.resolverinfo

# start/restart
sudo systemctl restart bind9

# Check if BIND is running
sudo systemctl status bind9

# for troubleshooting and error infos
sudo named-checkconf

# service logs
sudo journalctl -xeu bind9
