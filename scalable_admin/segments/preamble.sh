#!/bin/bash -v

# Define some helper functions
function error_exit {{
    echo "ERROR: $1"
    /opt/aws/bin/cfn-signal -e 1 -r "$1" --stack {AWS::StackName} --resource %%RESOURCE%% --region {AWS::Region}
    exit 1
}}

function loop {{
    original=$1
    remaining=$1
    shift
    while [ $remaining -gt 0 ]; do
        if [ $original -ne $remaining ]; then
            sleep_time=$(expr $original - $remaining)
            echo -n "$* failed. Trying $remaining more time(s) "
            echo "after sleeping $sleep_time seconds."
            sleep $sleep_time
        fi
        $*
        if [ $? -eq 0 ]; then
            return 0
        else
            remaining=$(expr $remaining - 1)
        fi
    done
    return 1
}}

function user_sudo {{
    sudo -u ec2-user bash -lc "$*"
}}


# Run necessary updates
yum update -y aws-cfn-bootstrap

# Run cfn-init (see AWS::CloudFormation::Init)
/opt/aws/bin/cfn-init -s {AWS::StackName} -r AppServer --region {AWS::Region} || error_exit 'Failed to run cfn-init'

# Don't require tty to run sudo
sed -i 's/ requiretty/ !requiretty/' /etc/sudoers
