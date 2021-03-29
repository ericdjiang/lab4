sudo apt update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:wireshark-dev/stable
sudo apt update 
sudo DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends tshark arping git iputils-ping vim-nox python-setuptools python-all-dev flex bison traceroute openvswitch-testcontroller screen curl patch
sudo ln -s /usr/bin/ovs-testcontroller /usr/bin/ovs-controller
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
sudo pip install idna twisted

git clone git://github.com/mininet/mininet
cd mininet
./util/install.sh -fnv
cd ../ltprotocol
sudo python2 setup.py install
cd ../lab4
./config.sh
mkdir pcap_files
sudo chmod 777 pcap_files/
sudo apt-get purge -y --auto-remove
