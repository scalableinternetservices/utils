# Install Passenger
gem install passenger rake || error_exit 'Failed to install passenger gems'
# Build and install passenger
user_sudo /usr/local/bin/passenger start --runtime-check-only || error_exit 'Failed to build or install passenger'
