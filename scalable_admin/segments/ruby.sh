# Update alternatives
alternatives --set ruby /usr/bin/ruby2.1 || error_exit 'Failed ruby2.1 default'
# Install bundler only after the alternatives have been set.
gem install bundle || error_exit 'Failed to install bundle'
# Update user's path if it hasn't been set already
echo "export PATH=/usr/local/bin:\$PATH" >> /home/ec2-user/.bashrc
