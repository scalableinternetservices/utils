export HOME=/home/ec2-user/
ruby -e "require 'webrick'; WEBrick::HTTPServer.new(:DocumentRoot => '/home/ec2-user/.tsung/log').start" &
