#!/bin/bash -v
yum update -y aws-cfn-bootstrap
yum update -y
# Helper function
function error_exit {{
    echo "ERROR: $1"
    /opt/aws/bin/cfn-signal -e 1 -r "$1" --stack {AWS::StackName}       --resource %%RESOURCE%% --region {AWS::Region}
    exit 1
}}
# Run cfn-init (see AWS::CloudFormation::Init)
/opt/aws/bin/cfn-init -s {AWS::StackName} -r AppServer   --region {AWS::Region} || error_exit 'Failed to run cfn-init'
# Don't require tty to run sudo
sed -i 's/ requiretty/ !requiretty/' /etc/sudoers
function user_sudo {{
    sudo -u ec2-user bash -lc "$*"
}}
