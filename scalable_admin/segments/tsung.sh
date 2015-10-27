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

# Build Tsung
user_sudo wget http://tsung.erlang-projects.org/dist/tsung-1.6.0.tar.gz
user_sudo tar -xvzf tsung-1.6.0.tar.gz
cd tsung-1.6.0
user_sudo ./configure
user_sudo make
make install

# Clean up
cd ..
user_sudo rm -rf tsung-1.6.0*

# Start simple HTTP Server for Results
ruby -e "require 'webrick'; WEBrick::HTTPServer.new(:DocumentRoot => '/home/ec2-user/.tsung/log').start" &
