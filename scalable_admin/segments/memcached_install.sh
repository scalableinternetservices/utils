# Install dalli gem (for memcached)
tmp="gem 'dalli'"; grep "^$tmp" Gemfile > /dev/null || echo $tmp >> Gemfile;     unset tmp
user_sudo bundle install || error_exit 'Failed to install dalli'
