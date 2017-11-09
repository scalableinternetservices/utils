# Set environment variable
echo "export PATH=/usr/lib/tsung/bin:\$PATH" >> /home/ec2-user/.bashrc

# Redirect port 80 to port 8091 (tsung server port)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8091

ln -s /home/ec2-user/.tsung/log /home/ec2-user/tsung_logs
