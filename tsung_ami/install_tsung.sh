export VERSION=tsung-1.7.0

sudo yum update --assumeyes
sudo yum install gcc gnuplot ncurses-compat-libs perl-Template-Toolkit --assumeyes

# Set open file limits for ec2-user
echo "ec2-user hard nofile 42946" | sudo tee -a /etc/security/limits.conf
echo "ec2-user soft nofile 42946" | sudo tee -a /etc/security/limits.conf

# Install erlc
wget https://github.com/rabbitmq/erlang-rpm/releases/download/v22.2/erlang-22.2-1.el7.x86_64.rpm
sudo rpm -i erlang-22.2-1.el7.x86_64.rpm
rm erlang-22.2-1.el7.x86_64.rpm

# Install matplotlib (for tsplot)
wget https://bootstrap.pypa.io/get-pip.py
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
