# Change to the app directory
cd /home/ec2-user/app
# Add environment variables to ec2-user's .bashrc
export RAILS_ENV=production
echo "export RAILS_ENV=production" >> ../.bashrc
echo "export SECRET_KEY_BASE=b801783afb83bb8e614b32ccf6c05c855a927116d92062a75c6ffa61d58c58e62f13eb60cf1a31922c44b7e6a3e8f1809934a93llask938bl" >> ../.bashrc

# Redirect port 80 to port 3000 (ec2-user cannot bind port 80)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3000

# Run the app specific ec2 initialization
if [ -f .ec2_initialize ]; then
    sudo -u ec2-user bash -l .ec2_initialize || error_exit 'Failed to run .ec2_initialize'
fi

# Add gems needed on production
echo -e "
gem 'therubyracer', platforms: :ruby " >> Gemfile
echo -e "
gem 'mysql2', '~> 0.3.13', platforms: :ruby " >> Gemfile
echo -e "
gem 'therubyrhino', platforms: :jruby " >> Gemfile
echo -e "
gem 'activerecord-jdbc-adapter', platforms: :jruby " >> Gemfile
echo -e "
gem 'multi_json'" >> Gemfile

# Run the remaining commands as the ec2-user in the app directory
loop 4 user_sudo bundle install --without test development || error_exit 'Failed to install bundle'
loop 8 user_sudo rake db:create db:migrate || error_exit 'Failed to execute database migration'

# Run the app specific ec2 initialization
if [ -f .rails_initialize ]; then
    sudo -u ec2-user bash -l .rails_initialize || error_exit 'Failed to run .rails_initialize'
fi

# Generate static assets
user_sudo rake assets:precompile || error_exit 'Failed to precompile static assets'
