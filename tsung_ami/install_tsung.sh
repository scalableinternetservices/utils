set -e

export VERSION=tsung-1.7.0

sudo yum update --assumeyes
sudo yum install gcc gnuplot iptables-services ncurses-compat-libs perl-Template-Toolkit --assumeyes

# Set open file limits for ec2-user
echo "ec2-user hard nofile 42946" | sudo tee -a /etc/security/limits.conf
echo "ec2-user soft nofile 42946" | sudo tee -a /etc/security/limits.conf

# Start iptables service
sudo systemctl enable iptables
sudo systemctl start iptables

# Redirect port 80 to port 8091 (tsung server port)
sudo iptables -F
sudo iptables -X
sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8091
sudo service iptables save

# Install erlc
wget https://github.com/rabbitmq/erlang-rpm/releases/download/v22.2/erlang-22.2-1.el7.x86_64.rpm
sudo rpm -i erlang-22.2-1.el7.x86_64.rpm
rm erlang-22.2-1.el7.x86_64.rpm

# Install matplotlib (for tsplot)
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
sudo python get-pip.py
rm get-pip.py
sudo pip install matplotlib

# Install tsung
wget http://tsung.erlang-projects.org/dist/$VERSION.tar.gz
tar -xzf $VERSION.tar.gz
rm $VERSION.tar.gz
cd $VERSION
./configure
make
sudo make install
cd -
rm -r $VERSION/


# Make logs more accessible
ln -s /home/ec2-user/.tsung/log /home/ec2-user/tsung_logs
