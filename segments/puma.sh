# Configure the app to serve static assets
echo -e "
gem 'puma' " >> /home/ec2-user/app/Gemfile
cd /home/ec2-user/app
if [ '{RubyVM}' == 'JRuby' ]; then
  gpg --keyserver hkp://keys.gnupg.net   --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3
  curl -sSL https://get.rvm.io | bash -s stable
  echo "source /home/ec2-user/.profile" >> /home/ec2-user/.bash_profile
  source /home/ec2-user/.profile
  rvm install jruby-1.7.19
  rvm --default use jruby-1.7.19
  sudo yum install mysql-connector-java
  echo "\$CLASSPATH ||= [] " >> config/application.rb;
  echo "\$CLASSPATH << '/usr/share/java/mysql-connector-java.jar'"    >> config/application.rb;
fi
user_sudo "bundle install"
user_sudo RAILS_SERVE_STATIC_FILES=true bundle exec puma -t {ThreadParallelism} -w {ProcessParallelism} -p 3000 -d || error_exit 'Failed to start rails server'
