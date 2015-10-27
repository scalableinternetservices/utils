# Install tsung environment
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
export HOME=/home/ec2-user/
cd $HOME/
user_sudo mkdir /home/ec2-user/opt
user_sudo wget http://www.erlang.org/download/otp_src_R16B03-1.tar.gz
user_sudo tar xzf otp_src_R16B03-1.tar.gz
cd otp_src_R16B03-1
user_sudo ./configure --prefix=/home/ec2-user/opt/erlang-R16B03-1
user_sudo make install
user_sudo echo 'pathmunge /home/ec2-user/opt/erlang-R16B03-1/bin' > /etc/profile.d/erlang.sh
user_sudo chmod +x /etc/profile.d/erlang.sh
user_sudo pathmunge /home/ec2-user/opt/erlang-R16B03-1/bin
cd $HOME
user_sudo wget http://tsung.erlang-projects.org/dist/tsung-1.5.0.tar.gz
user_sudo tar xzf tsung-1.5.0.tar.gz
cd tsung-1.5.0
user_sudo ./configure --prefix=$HOME/opt/tsung-1.5.0
user_sudo make install
cpan Template
user_sudo echo 'pathmunge /home/ec2-user/opt/tsung-1.5.0/bin' > /etc/profile.d/tsung.sh
user_sudo echo 'pathmunge /home/ec2-user/opt/tsung-1.5.0/lib/tsung/bin' >> /etc/profile.d/tsung.sh
ruby -e "require 'webrick'; WEBrick::HTTPServer.new(:DocumentRoot => '/home/ec2-user/.tsung/log').start" &
# All is well so signal success
/opt/aws/bin/cfn-signal -e 0 --stack
true || error_exit 'Error installing tsung'
