# Fix weak etags issue
echo -e "
gem 'rails_weak_etags'" >> /home/ec2-user/app/Gemfile
user_sudo "bundle install"
# Install Passenger
gem install passenger rake || error_exit 'Failed to install passenger gems'
# Build and install passenger
user_sudo /usr/local/bin/passenger start --runtime-check-only || error_exit 'Failed to build or install passenger'
# Start passenger
user_sudo passenger start -d --no-compile-runtime || error_exit 'Failed to start passenger'
