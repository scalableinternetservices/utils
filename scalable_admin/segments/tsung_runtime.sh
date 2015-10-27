# Start simple HTTP Server for Results
ruby -e "require 'webrick'; WEBrick::HTTPServer.new(:DocumentRoot => '/home/ec2-user/.tsung/log').start" &
