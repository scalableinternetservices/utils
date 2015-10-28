# Install tsung environment

# Prepare Environment Variables
echo "*  soft  nofile  1024000" | tee -a /etc/security/limits.conf || error_exit 'Error setting nofile limits'
echo "*  hard  nofile  1024000" | tee -a /etc/security/limits.conf || error_exit 'Error setting nofile limits'
echo "net.core.rmem_max = 16777216" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.core.wmem_max = 16777216" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_rmem = 4096 87380 16777216" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_wmem = 4096 65536 16777216" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_mem = 50576 64768 98152" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.core.netdev_max_backlog = 2048" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.core.somaxconn = 1024" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_max_syn_backlog = 2048" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_syncookies = 1" | tee -a /etc/sysctl.conf || error_exit 'Error setting sysctl config'
sysctl -p

# Change to the app directory
cd /home/ec2-user/

# Fetch tsung example
wget https://raw.githubusercontent.com/scalableinternetservices/demo/master/load_tests/simple.xml

# Build Tsung
user_sudo wget http://tsung.erlang-projects.org/dist/tsung-1.6.0.tar.gz || error_exit 'Failed to download tsung.'
user_sudo tar -xvzf tsung-1.6.0.tar.gz || error_exit 'Failed to extract tsung'
cd tsung-1.6.0
user_sudo ./configure  || error_exit 'Failed to configure tsung'
user_sudo make || error_exit 'Failed to make tsung'
make install || error_exit 'Failed to install tsung'

# Clean up
cd ..
user_sudo rm -rf tsung-1.6.0*

# Redirect port 80 to port 8091 (tsung server port)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8091
