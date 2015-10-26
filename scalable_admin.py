#!/usr/bin/env python

"""Scalable Internet Services administrative utility.

Usage:
  admin aws TEAM...
  admin aws-cleanup
  admin aws-purge TEAM...
  admin aws-update-all
  admin cftemplate [--no-test] [--app-ami=ami] [--multi] [--puma] [--memcached]
  admin cftemplate tsung [--no-test] [--app-ami=ami]
  admin cftemplate passenger-ami
  admin cftemplate tsung-ami
  admin cftemplate-update-all [--no-test] [--passenger-ami=ami]
  admin gh TEAM USER...

-h --help  show this message
"""  # NOQA

from __future__ import print_function
from datetime import datetime, timedelta, tzinfo
from docopt import docopt
from pprint import pprint
from string import Formatter
import botocore.exceptions
import botocore.session
import copy
import json
import os
import random
import string
import sys


__version__ = '0.1'


# Update this value for your github organization.
GH_ORGANIZATION = 'scalableinternetservices'

# Update this value for your class's S3 bucket.
# Cloudformation templates are stored in this bucket, and each TEAM will have
# PUT/GET permissions to `S3_BUCKET/TEAMNAME/`
S3_BUCKET = 'scalableinternetservices'


class AWS(object):
    """This class handles AWS administrative tasks."""

    EC2_INSTANCES = ['t2.micro',
                     'm3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                     'c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge',
                     'r3.large', 'r3.xlarge', 'r3.2xlarge']
    RDB_INSTANCES = ['db.{0}'.format(x) for x in EC2_INSTANCES]
    REGION = 'us-west-2'
    ARNCF = 'arn:aws:cloudformation:{0}:*:{{0}}'.format(REGION)
    ARNEC2 = 'arn:aws:ec2:{0}:*:{{0}}'.format(REGION)
    ARNELB = ('arn:aws:elasticloadbalancing:{0}:*:loadbalancer/{{0}}'
              .format(REGION))
    ARNRDS = 'arn:aws:rds:{0}:*:db:{{0}}'.format(REGION)
    ARNRDSSUB = 'arn:aws:rds:{0}:*:subgrp:{{0}}'.format(REGION)
    POLICY = {'Statement':
              [{'Action': ['autoscaling:*',  # No fine grained permissions
                           'cloudformation:CreateUploadBucket',
                           'cloudformation:Describe*',
                           'cloudformation:Get*',
                           'cloudformation:ListStack*',
                           'cloudformation:ValidateTemplate',
                           'cloudwatch:DescribeAlarms',
                           'cloudwatch:GetMetricStatistics',
                           'elasticloadbalancing:Describe*', 'rds:Describe*',
                           'iam:ListServerCertificates',
                           'rds:ListTagsForResource',
                           'sts:DecodeAuthorizationMessage'],
                'Effect': 'Allow', 'Resource': '*'},
               {'Action': ['ec2:Describe*'],
                'Condition': {'StringEquals': {'ec2:Region': REGION}},
                'Effect': 'Allow', 'Resource': '*'},
               {'Action': ['s3:Get*', 's3:Put*'], 'Effect': 'Allow',
                'Resource': 'arn:aws:s3:::cf-templates*{0}*'.format(REGION)}]}
    GROUP = 'scalableinternetservices'
    PROFILE = 'admin'

    @staticmethod
    def op(method, debug_output=True, **kwargs):
        """Execute an AWS operation and check the response status."""
        try:
            response = method(**kwargs)
        except botocore.exceptions.ClientError as exc:
            sys.stderr.write(exc.message)
            sys.stderr.write('\n')
            return False
        except:
            raise
        if debug_output:
            sys.stderr.write('Success: {0} {1}\n'
                             .format(method.__name__, kwargs))
        return response

    @staticmethod
    def operation_list(service_name):
        """Output the available API commands and exit."""
        pprint(service_name[0].operations)
        sys.exit(1)

    def __init__(self):
        """Initialize the AWS class."""
        self.aws = botocore.session.Session(profile=self.PROFILE)
        self.ec2 = self.aws.create_client('ec2', self.REGION)
        self.iam = self.aws.create_client('iam', None)
        self.rds = self.aws.create_client('rds', self.REGION)

    def az_to_subnet(self):
        """Return a mapping of availability zone to their subnet."""
        vpc = self.op(self.ec2.describe_vpcs)['Vpcs'][0]
        subnets = self.op(self.ec2.describe_subnets, Filters=[
            {'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])['Subnets']
        return {x['AvailabilityZone']: {'subnet': x['SubnetId']}
                for x in subnets}

    def cleanup(self):
        """Clean up old stacks and EC2 instances."""
        cf = self.aws.create_client('cloudformation', self.REGION)
        now = datetime.now(UTC())
        for stack in self.op(cf.list_stacks, False)['StackSummaries']:
            if stack['StackStatus'] in {'DELETE_COMPLETE'}:
                continue
            if now - stack['CreationTime'] > timedelta(hours=8):
                self.op(cf.delete_stack, StackName=stack['StackName'])

    def configure(self, team):
        """Create account and configure settings for a team.

        This method can be run subsequent times to apply team updates.
        """
        s3_statement = [
            {'Action': '*', 'Effect': 'Allow',
             'Resource': 'arn:aws:s3:::{0}/{1}/*'.format(S3_BUCKET, team)},
            {'Action': 's3:ListBucket', 'Effect': 'Allow',
             'Condition': {'StringLike': {'s3:prefix': '{0}/*'.format(team)}},
             'Resource': 'arn:aws:s3:::{0}'.format(S3_BUCKET)}]

        # Create IAM role (permits S3 access from associated EC2 instances)
        role_policy = {'Statement': {
            'Action': 'sts:AssumeRole',
            'Effect': 'Allow',
            'Principal': {'Service': 'ec2.amazonaws.com'}}}
        self.op(self.iam.create_instance_profile, InstanceProfileName=team)
        self.op(self.iam.create_role, RoleName=team,
                AssumeRolePolicyDocument=json.dumps(role_policy))
        self.op(self.iam.add_role_to_instance_profile, RoleName=team,
                InstanceProfileName=team)
        self.op(self.iam.put_role_policy, RoleName=team, PolicyName=team,
                PolicyDocument=json.dumps({'Statement': s3_statement}))

        # Create IAM group if it does not exist
        self.op(self.iam.create_group, GroupName=self.GROUP)
        self.op(self.iam.put_group_policy, GroupName=self.GROUP,
                PolicyName=self.GROUP, PolicyDocument=json.dumps(self.POLICY))

        # Configure user account / password / access keys / keypair
        if self.op(self.iam.create_user, UserName=team):
            password = generate_password()
            self.op(self.iam.create_login_profile, UserName=team,
                    Password=password)
            data = self.op(self.iam.create_access_key, UserName=team)
            if data:
                filename = '{0}.txt'.format(team)
                with open(filename, 'w') as fp:
                    fp.write('Username: {0}\n'.format(team))
                    fp.write('Password: {0}\n'.format(password))
                filename = '{0}_key.txt'.format(team)
                with open(filename, 'w') as fp:
                    fp.write('AccessKey: {0}\n'
                             .format(data['AccessKey']['AccessKeyId']))
                    fp.write('SecretKey: {0}\n'
                             .format(data['AccessKey']['SecretAccessKey']))
                print('Login and key info saved as: {0}'.format(filename))
            data = self.op(self.ec2.create_key_pair, KeyName=team)
            if data:
                filename = '{0}.pem'.format(team)
                with open(filename, 'w') as fd:
                    os.chmod(filename, 0o600)
                    fd.write(data['KeyMaterial'])
                print('Keypair saved as: {0}'.format(filename))
        self.op(self.iam.add_user_to_group, GroupName=self.GROUP,
                UserName=team)

        # Configure security groups
        vpc = self.op(self.ec2.describe_vpcs)['Vpcs'][0]
        retval = self.op(self.ec2.create_security_group, GroupName=team,
                         Description=team, VpcId=vpc['VpcId'])
        if retval:
            group_id = retval['GroupId']
        else:
            group_id = self.op(
                self.ec2.describe_security_groups,
                Filters=[{'Name': 'group-name', 'Values': [team]}]
            )['SecurityGroups'][0]['GroupId']

        for port in [22, 80, 443]:  # Open standard ports to all addresses.
            # These are run one at a time so that existance of one doesn't
            # prevent the creation of the others.
            rule = {'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            self.op(self.ec2.authorize_security_group_ingress,
                    GroupId=group_id, IpPermissions=[rule])

        # Create RDS Subgroups
        subnets = [x['subnet'] for x in self.az_to_subnet().values()]
        self.op(self.rds.create_db_subnet_group, DBSubnetGroupDescription=team,
                DBSubnetGroupName=team, SubnetIds=subnets)

        # Permit all instances in the SecurityGroup to talk to each other
        self.op(self.ec2.authorize_security_group_ingress, GroupId=group_id,
                IpPermissions=[
                    {'IpProtocol': '-1', 'FromPort': 0, 'ToPort': 65535,
                     'UserIdGroupPairs': [{'GroupId': group_id}]}])

        policy = {'Statement': []}
        # State-based policies
        policy['Statement'].append(
            {'Action': ['cloudformation:CreateStack',
                        'cloudformation:DeleteStack',
                        'cloudformation:UpdateStack'],
             'Effect': 'Allow',
             'Resource': AWS.ARNCF.format('stack/{0}*'.format(team))})
        policy['Statement'].append(
            {'Action': ['ec2:RebootInstances', 'ec2:StartInstances',
                        'ec2:StopInstances', 'ec2:TerminateInstances'],
             'Condition': {
                 'StringLike': {
                     'ec2:ResourceTag/aws:cloudformation:stack-name':
                     '{0}*'.format(team)}},
             'Effect': 'Allow', 'Resource': AWS.ARNEC2.format('instance/*')})
        policy['Statement'].append(
            {'Action': 'elasticloadbalancing:*',
             'Effect': 'Allow',
             'Resource': AWS.ARNELB.format('{0}*'.format(team))})
        policy['Statement'].append(
            {'Action': ['rds:DeleteDBInstance', 'rds:RebootDBInstance'],
             'Effect': 'Allow',
             'Resource': AWS.ARNRDS.format('{0}*'.format(team).lower())})
        # Creation policies
        policy['Statement'].append(
            {'Action': 'ec2:RunInstances',
             'Effect': 'Allow',
             'Resource': [AWS.ARNEC2.format('image/*'),
                          AWS.ARNEC2.format('key-pair/{0}'.format(team)),
                          AWS.ARNEC2.format('network-interface/*'),
                          AWS.ARNEC2.format('security-group/*'),
                          AWS.ARNEC2.format('subnet/*'),
                          AWS.ARNEC2.format('volume/*')]})
        # Allow teams to add their own SSL certificate
        policy['Statement'].append(
            {'Action': 'iam:UploadServerCertificate',
             'Effect': 'Allow',
             'Resource': 'arn:aws:iam::*:server-certificate/{0}'.format(team)})
        # Allow teams to use their team roles
        policy['Statement'].append(
            {'Action': 'iam:PassRole',
             'Effect': 'Allow',
             'Resource': 'arn:aws:iam::*:role/{0}'.format(team)})
        # Allow full access to S3_BUCKET/TEAM in S3
        policy['Statement'].extend(s3_statement)
        # Filter the EC2 instances types that are allowed to be started
        policy['Statement'].append(
            {'Action': 'ec2:RunInstances',
             'Condition': {
                 'StringLike': {'ec2:InstanceType': self.EC2_INSTANCES}},
             'Effect': 'Allow',
             'Resource': AWS.ARNEC2.format('instance/*')})
        # Filter the RDS instance types that are allowed to be started
        policy['Statement'].append(
            {'Action': ['rds:CreateDBInstance', 'rds:ModifyDBInstance'],
             'Condition': {
                 'Bool': {'rds:MultiAz': 'false'},
                 'NumericEquals': {'rds:Piops': '0', 'rds:StorageSize': '5'},
                 'StringEquals': {'rds:DatabaseEngine': 'mysql'},
                 'StringLike': {'rds:DatabaseClass': self.RDB_INSTANCES}},
             'Effect': 'Allow',
             'Resource': [AWS.ARNRDS.format('{0}*'.format(team).lower()),
                          AWS.ARNRDSSUB.format('{0}'.format(team).lower())]})

        # Create and associate TEAM group (can have longer policy lists)
        self.op(self.iam.create_group, GroupName=team)
        self.op(self.iam.put_group_policy, GroupName=team, PolicyName=team,
                PolicyDocument=json.dumps(policy))
        self.op(self.iam.add_user_to_group, GroupName=team,  UserName=team)
        return 0

    def team_to_security_group(self):
        """Return a mapping of teams to their security groups."""
        data = self.op(self.ec2.describe_security_groups, debug_output=False)
        return {x['GroupName']: {'sg': x['GroupId']} for x in
                data['SecurityGroups']
                if not x['GroupName'].startswith('default')}

    def purge(self, team):
        """Remove all settings pertaining to `team`."""
        # Remove IAM Role
        self.op(self.iam.remove_role_from_instance_profile, RoleName=team,
                InstanceProfileName=team)
        self.op(self.iam.delete_role_policy, RoleName=team,
                PolicyName=team)
        self.op(self.iam.delete_role, RoleName=team)
        # Remove IAM User and Group
        self.op(self.iam.delete_login_profile, UserName=team)
        resp = self.op(self.iam.list_access_keys, UserName=team)
        if resp:
            for keydata in resp['AccessKeyMetadata']:
                self.op(self.iam.delete_access_key, UserName=team,
                        AccessKeyId=keydata['AccessKeyId'])
        # Remove user from groups
        group_response = self.op(self.iam.list_groups_for_user, UserName=team)
        groups = group_response['Groups'] if group_response else []
        for group in groups:
            group_name = group['GroupName']
            self.op(self.iam.remove_user_from_group, GroupName=group_name,
                    UserName=team)
            if not self.op(self.iam.get_group, GroupName=group_name)['Users']:
                # Delete group
                self.op(self.iam.delete_group_policy, GroupName=group_name,
                        PolicyName=group_name)
                self.op(self.iam.delete_group, GroupName=group_name)
        self.op(self.iam.delete_user, UserName=team)
        self.op(self.ec2.delete_key_pair, KeyName=team)

        group_id = self.op(
            self.ec2.describe_security_groups,
            Filters=[{'Name': 'group-name', 'Values': [team]}]
        )['SecurityGroups'][0]['GroupId']
        self.op(self.ec2.delete_security_group, GroupId=group_id)
        self.op(self.rds.delete_db_subnet_group, DBSubnetGroupName=team)
        return 0

    def verify_template(self, template, upload=None):
        """Verify a cloudformation template.

        :param upload: When provided, it should be a tuple containing the
            bucket and key to upload the template to. If the template is valid,
            it will be uploaded to this s3 bucket, and the URL to the template
            in S3 will be returned. Note that this URL is not publicly
            accessible, but it will work for CloudFormation Stack generation.
        """
        cf = self.aws.create_client('cloudformation', self.REGION)
        valid = bool(self.op(cf.validate_template, TemplateBody=template,
                             debug_output=False))
        if not valid or upload is None:
            return valid
        # Upload to s3
        bucket, key = upload
        s3 = self.aws.create_client('s3', None)
        retval = self.op(s3.put_object, Bucket=bucket, Key=key, Body=template,
                         ACL='public-read', debug_output=False)

        if not retval:
            return retval
        return 'https://{0}.s3.amazonaws.com/{1}'.format(bucket, key)


class CFTemplate(object):
    """Generate Scalable Internet Services Cloudformation templates."""

    DEFAULT_AMIS = {'us-east-1': {'ebs': 'ami-e3106686',
                                  'instance': 'ami-65116700'},
                    'us-west-2': {'ebs': 'ami-9ff7e8af',
                                  'instance': 'ami-bbf7e88b'}}
    DEFAULT_INSTANCE = 't2.micro'
    DEFAULT_MULTI_INSTANCE = 'm3.medium'
    # The following strings are python-format strings, however, the values
    # between brackets will be replaced with `{'Ref': 'value'}`. Make sure to
    # escape intended brackets: '{' => '{{', '}' => '}}'
    INIT = {'preamble': """#!/bin/bash -v
yum update -y aws-cfn-bootstrap
yum update
# Helper function
function error_exit {{
    /opt/aws/bin/cfn-signal -e 1 -r "$1" --stack {AWS::StackName} \
      --resource %%RESOURCE%% --region {AWS::Region}
    exit 1
}}
# Run cfn-init (see AWS::CloudFormation::Init)
/opt/aws/bin/cfn-init -s {AWS::StackName} -r AppServer \
  --region {AWS::Region} || error_exit 'Failed to run cfn-init'
# Don't require tty to run sudo
sed -i 's/ requiretty/ !requiretty/' /etc/sudoers
function user_sudo {{
    sudo -u ec2-user bash -lc "$*"
}}
""",
            'tsung': """# Install tsung environment
echo "*  soft  nofile  1024000" | tee -a /etc/security/limits.conf\
 || error_exit 'Error setting nofile limits'
echo "*  hard  nofile  1024000" | tee -a /etc/security/limits.conf\
 || error_exit 'Error setting nofile limits'
echo "net.core.rmem_max = 16777216" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.core.wmem_max = 16777216" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_rmem = 4096 87380 16777216" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_wmem = 4096 65536 16777216" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_mem = 50576 64768 98152" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.core.netdev_max_backlog = 2048" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.core.somaxconn = 1024" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_max_syn_backlog = 2048" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
echo "net.ipv4.tcp_syncookies = 1" | tee -a /etc/sysctl.conf\
 || error_exit 'Error setting sysctl config'
sysctl -p
export HOME=/home/ec2-user/
cd $HOME/
user_sudo mkdir /home/ec2-user/opt
user_sudo wget http://www.erlang.org/download/otp_src_R16B03-1.tar.gz
user_sudo tar xzf otp_src_R16B03-1.tar.gz
cd otp_src_R16B03-1
user_sudo ./configure --prefix=/home/ec2-user/opt/erlang-R16B03-1
user_sudo make install
user_sudo echo 'pathmunge /home/ec2-user/opt/erlang-R16B03-1/bin'\
 > /etc/profile.d/erlang.sh
user_sudo chmod +x /etc/profile.d/erlang.sh
user_sudo pathmunge /home/ec2-user/opt/erlang-R16B03-1/bin
cd $HOME
user_sudo wget http://tsung.erlang-projects.org/dist/tsung-1.5.0.tar.gz
user_sudo tar xzf tsung-1.5.0.tar.gz
cd tsung-1.5.0
user_sudo ./configure --prefix=$HOME/opt/tsung-1.5.0
user_sudo make install
cpan Template
user_sudo echo 'pathmunge /home/ec2-user/opt/tsung-1.5.0/bin'\
 > /etc/profile.d/tsung.sh
user_sudo echo 'pathmunge /home/ec2-user/opt/tsung-1.5.0/lib/tsung/bin'\
 >> /etc/profile.d/tsung.sh
ruby -e "require 'webrick'; WEBrick::HTTPServer.new(:DocumentRoot =>\
 '/home/ec2-user/.tsung/log').start" &
# All is well so signal success
/opt/aws/bin/cfn-signal -e 0 --stack
true || error_exit 'Error installing tsung'
""",
            'tsung_runtime': """export HOME=/home/ec2-user/
ruby -e "require 'webrick'; WEBrick::HTTPServer.new(:DocumentRoot =>\
 '/home/ec2-user/.tsung/log').start" &
""",
            'memcached_configure_multi': """# Configure rails to use dalli
sed -i 's/# config.cache_store = :mem_cache_store/config.cache_store =\
 :dalli_store, "{Memcached,PublicIp}"/' config/environments/production.rb
""",
            'memcached_configure_single': """# Configure rails to use dalli
sed -i 's/# config.cache_store = :mem_cache_store/config.cache_store =\
 :dalli_store/' config/environments/production.rb
""",
            'memcached_install': """# Install dalli gem (for memcached)
tmp="gem 'dalli'"; grep "^$tmp" Gemfile > /dev/null || echo $tmp >> Gemfile; \
    unset tmp
user_sudo bundle install || error_exit 'Failed to install dalli'
""",
            'ruby': """# Update alternatives
alternatives --set ruby /usr/bin/ruby2.1 || error_exit 'Failed ruby2.1 default'
# Install bundler only after the alternatives have been set.
gem install bundle || error_exit 'Failed to install bundle'
# Update user's path if it hasn't been set already
echo "export PATH=/usr/local/bin:\$PATH" >> /home/ec2-user/.bashrc
""",
            'rails': """# Change to the app directory
cd /home/ec2-user/app
# Add environment variables to ec2-user's .bashrc
export RAILS_ENV=production
echo "export RAILS_ENV=production" >> ../.bashrc
echo "export SECRET_KEY_BASE=b801783afb83bb8e614b32ccf6c05c855a927116d92062a75\
c6ffa61d58c58e62f13eb60cf1a31922c44b7e6a3e8f1809934a93llask938bl" >> ../.bashrc

# Redirect port 80 to port 3000 (ec2-user cannot bind port 80)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3000

# Run the app specific ec2 initialization
if [ -f .ec2_initialize ]; then
    sudo -u ec2-user bash -l .ec2_initialize\
     || error_exit 'Failed to run .ec2_initialize'
fi

# Add gems needed on production
echo -e "\ngem 'therubyracer', platforms: :ruby " >> Gemfile
echo -e "\ngem 'mysql2', '~> 0.3.13', platforms: :ruby " >> Gemfile
echo -e "\ngem 'therubyrhino', platforms: :jruby " >> Gemfile
echo -e "\ngem 'activerecord-jdbc-adapter', platforms: :jruby " >> Gemfile
echo -e "\ngem 'multi_json'" >> Gemfile

# Run the remaining commands as the ec2-user in the app directory
user_sudo bundle install --without test development\
 || error_exit 'Failed to install bundle'
# Create the database and run the migrations (try up to 10x)
loop=10
while [ $loop -gt 0 ]; do
  user_sudo rake db:create db:migrate
  if [ $? -eq 0 ]; then
    loop=-1
  else
    sleep 6
    loop=$(expr $loop - 1)
  fi
done
if [ $loop -eq 0 ]; then
  error_exit 'Failed to execute database migration'
fi
# Run the app specific ec2 initialization
if [ -f .rails_initialize ]; then
    sudo -u ec2-user bash -l .rails_initialize\
     || error_exit 'Failed to run .rails_initialize'
fi
# Generate static assets
user_sudo rake assets:precompile\
 || error_exit 'Failed to precompile static assets'
""",
            'passenger': """# Start passenger
user_sudo passenger start -d --no-compile-runtime\
 || error_exit 'Failed to start passenger'
""",
            'puma': """# Configure the app to serve static assets
echo -e "\ngem 'puma' " >> /home/ec2-user/app/Gemfile
cd /home/ec2-user/app
if [ '{RubyVM}' == 'JRuby' ]; then
  gpg --keyserver hkp://keys.gnupg.net\
   --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3
  curl -sSL https://get.rvm.io | bash -s stable
  echo "source /home/ec2-user/.profile" >> /home/ec2-user/.bash_profile
  source /home/ec2-user/.profile
  rvm install jruby-1.7.19
  rvm --default use jruby-1.7.19
  sudo yum install mysql-connector-java
  echo "\$CLASSPATH ||= [] " >> config/application.rb;
  echo "\$CLASSPATH << '/usr/share/java/mysql-connector-java.jar'"\
    >> config/application.rb;
fi
user_sudo "bundle install"
user_sudo RAILS_SERVE_STATIC_FILES=true bundle exec puma\
 -t {ThreadParallelism} -w {ProcessParallelism} -p 3000 -d\
 || error_exit 'Failed to start rails server'
""",
            'passenger-install': """# Install Passenger
gem install passenger rake || error_exit 'Failed to install passenger gems'
# Build and install passenger
user_sudo /usr/local/bin/passenger start --runtime-check-only\
 || error_exit 'Failed to build or install passenger'
""",
            'postamble': """# All is well so signal success
/opt/aws/bin/cfn-signal -e 0 --stack {AWS::StackName} --resource %%RESOURCE%% \
  --region {AWS::Region}
"""}
    PACKAGES = {'passenger': {'gcc-c++', 'libcurl-devel', 'make',
                              'openssl-devel', 'pcre-devel', 'ruby21-devel'},
                'stack': {'gcc-c++', 'git', 'make', 'mysql-devel',
                          'ruby21-devel'},
                'tsung': {'gcc', 'python27', 'git', 'autoconf',
                          'gnuplot',
                          'perl-CPAN', 'ncurses-devel', 'openssl-devel'}}
    TEMPLATE = {'AWSTemplateFormatVersion': '2010-09-09',
                'Outputs': {},
                'Parameters': {},
                'Resources': {}}

    @staticmethod
    def get_att(resource, attribute):
        """Apply the 'Fn::GetAtt' function on resource for attribute."""
        return {'Fn::GetAtt': [resource, attribute]}

    @staticmethod
    def get_map(mapping, key, value):
        """Apply the 'Fn::FindInMap' function."""
        return {'Fn::FindInMap': [mapping, key, value]}

    @staticmethod
    def get_ref(resource):
        """Apply the 'Ref' function for resource."""
        return {'Ref': resource}

    @staticmethod
    def join(*args):
        """Apply the 'Fn::Join' function to args using separator."""
        return {'Fn::Join': ['', args]}

    @staticmethod
    def join_format(string):
        """Convert formatted strings into the cloudformation join format."""
        retval = []
        for item in Formatter().parse(string):
            if item[0]:
                retval.append(item[0])
            if item[1]:
                if ',' in item[1]:
                    retval.append(CFTemplate.get_att(*item[1].split(',', 1)))
                else:
                    retval.append({'Ref': item[1]})
                    if item[2]:  # Correct the string when '::' is used
                        retval[-1]['Ref'] += ':' + item[2]
        return retval

    def __init__(self, test):
        """Initialize the CFTemplate class.

        :param test: When true, append 'Test' to generated template name.
        """
        self.ami = None
        self.create_timeout = 'PT10M'
        self.template = copy.deepcopy(self.TEMPLATE)
        self.test = test
        self.yum_packages = None
        self._subnet_map = None
        self._team_map = None

    @property
    def ami_map(self):
        """Return a mapping of instance type to their AMI."""
        def ami_type(instance_type):
            return {'t2.micro': 'ebs'}.get(instance_type, 'instance')

        return {x: {'ami': self.DEFAULT_AMIS[AWS.REGION][ami_type(x)]} for x in
                AWS.EC2_INSTANCES}

    @property
    def default_subnet(self):
        """Return the first subnet for the VPC."""
        return sorted(self.subnets)[0]

    @property
    def subnet_map(self):
        """Return a mapping of AZ to subnet."""
        if self._subnet_map is None:
            self._subnet_map = AWS().az_to_subnet()
        return self._subnet_map

    @property
    def subnets(self):
        """Return a list of VPC subnets."""
        return [x['subnet'] for x in self.subnet_map.values()]

    @property
    def team_map(self):
        """Return a mapping of teams to their security group."""
        if self._team_map is None:
            self._team_map = AWS().team_to_security_group()
        return self._team_map

    def _add_cleanup_output(self):
        clean = ['sudo yum clean all',
                 ('sudo find /var/log -type f -exec sudo truncate --size 0 '
                  '{} \;'),
                 'sudo rm -f /root/.ssh/authorized_keys',
                 'sudo rm -f /root/.bash_history',
                 'rm -f /home/ec2-user/.ssh/authorized_keys',
                 'rm -f /home/ec2-user/.bash_history']
        self.add_output('Cleanup', 'Commands to run before making snapshot',
                        '; '.join(clean))

    def add_apps(self):
        """Update either the EC2 instance or autoscaling group."""
        app = {'sources': {'/home/ec2-user/app': self.join(
            'https://github.com/{0}/'.format(GH_ORGANIZATION),
            self.get_ref('TeamName'), '/tarball/', self.get_ref('Branch'))}}
        if not self.multi:
            ENABLE = {'enabled': True, 'ensureRunning': True}
            app['services'] = {'sysvinit': {'mysqld': ENABLE}}
            if self.memcached:
                app['services']['sysvinit']['memcached'] = ENABLE
        perms = {'commands': {'update_permissions':
                              {'command': 'chown -R ec2-user:ec2-user .',
                               'cwd': '/home/ec2-user/'}}}
        db_yml = 'production:\n  adapter: mysql2\n  database: rails_app\n'
        if self.multi:
            db_yml = self.join(db_yml, '  host: ',
                               self.get_att('Database', 'Endpoint.Address'),
                               '\n  password: password\n')
        user = {'files':
                {'/home/ec2-user/app/config/database.yml': {
                    'content': db_yml, 'group': 'ec2-user',
                    'owner': 'ec2-user'}}}

        conf = self.template['Resources']['AppServer']
        conf['Metadata']['AWS::CloudFormation::Init'].update({
            'configSets': {'default': ['packages', 'app', 'perms', 'user']},
            'app': app, 'perms': perms, 'user': user})
        if self.multi:
            conf['Properties']['SecurityGroups'] = [self.get_map(
                'Teams', self.get_ref('TeamName'), 'sg')]
            conf['Type'] = 'AWS::AutoScaling::LaunchConfiguration'
        else:
            conf['CreationPolicy'] = {
                'ResourceSignal': {'Timeout': self.create_timeout}}
            conf['Properties']['SecurityGroupIds'] = [self.get_map(
                'Teams', self.get_ref('TeamName'), 'sg')]
            conf['Properties']['SubnetId'] = self.default_subnet

    def add_output(self, name, description, value):
        """Add a template output value."""
        self.template['Outputs'][name] = {'Description': description,
                                          'Value': value}

    def add_parameter(self, name, ptype='String', allowed=None, default=None,
                      description=None, error_msg=None, maxv=None, minv=None):
        """Add a template parameter."""
        param = {'Type': ptype}
        if allowed:
            param['AllowedValues'] = allowed
        if default:
            param['Default'] = default
        if description:
            param['Description'] = description
        if error_msg:
            param['ConstraintDescription'] = error_msg
        if maxv:
            param['MaxValue'] = maxv
        if minv:
            param['MinValue'] = minv
        self.template['Parameters'][name] = param

    def add_ssh_output(self, resource_name='AppServer'):
        """Output the SSH connection string."""
        self.add_output('SSH', '{0} SSH connect string'.format(resource_name),
                        self.join(
            'ssh -i ', self.get_ref('TeamName'), '.pem ec2-user@',
            self.get_att(resource_name, 'PublicIp')))

    def callback_single_server(self):
        """Update the template parameters for a single-server instance."""
        self.template['Resources']['AppServer']['CreationPolicy'] = {
            'ResourceSignal': {'Timeout': self.create_timeout}}

    def callback_stack(self):
        """Update the template parameters for the stack."""
        self.add_parameter('Branch', default='master',
                           description='The git branch to deploy.')

        if self.puma:
            self.add_parameter('ProcessParallelism', default='1',
                               description='The number of worker processes.')
            self.add_parameter('ThreadParallelism', default='1',
                               description=('The number of threads within each'
                                            ' worker processes.'))
            self.add_parameter('RubyVM', default='MRI',
                               allowed=['MRI', 'JRuby'],
                               description=('The number of threads within each'
                                            ' worker processes.'))

        if self.multi:
            url = self.get_att('LoadBalancer', 'DNSName')
            self.add_parameter('AppInstances', 'Number', default=2,
                               description=('The number of AppServer instances'
                                            ' to launch.'),
                               maxv=8, minv=1)
            self.add_parameter('DBInstanceType', allowed=AWS.RDB_INSTANCES,
                               default='db.{0}'.format(
                                   self.DEFAULT_MULTI_INSTANCE),
                               description='The Database instance type.')
            self.template['Resources']['AppGroup'] = {
                'CreationPolicy': {'ResourceSignal': {
                    'Count': self.get_ref('AppInstances'),
                    'Timeout': self.create_timeout}},
                'Properties': {
                    'LaunchConfigurationName':
                    self.get_ref('AppServer'),
                    'LoadBalancerNames': [self.get_ref('LoadBalancer')],
                    'MaxSize': self.get_ref('AppInstances'),
                    'MinSize': self.get_ref('AppInstances'),
                    'VPCZoneIdentifier': self.subnets},
                'Type': 'AWS::AutoScaling::AutoScalingGroup'}
            self.template['Resources']['Database'] = {
                'Properties': {
                    'AllocatedStorage': 5,
                    'BackupRetentionPeriod': 0,
                    'DBInstanceClass': self.get_ref('DBInstanceType'),
                    'DBInstanceIdentifier': self.get_ref('AWS::StackName'),
                    'DBName': 'rails_app',
                    'DBSubnetGroupName': self.get_ref('TeamName'),
                    'Engine': 'mysql',
                    'MasterUsername': 'root',
                    'MasterUserPassword': 'password',
                    'VPCSecurityGroups': [self.get_map(
                        'Teams', self.get_ref('TeamName'), 'sg')]},
                'Type': 'AWS::RDS::DBInstance'}
            self.template['Resources']['LoadBalancer'] = {
                'Properties': {
                    'LBCookieStickinessPolicy': [
                        {'PolicyName': 'CookiePolicy',
                         'CookieExpirationPeriod': 30}],
                    'LoadBalancerName': self.get_ref('AWS::StackName'),
                    'Listeners': [{'InstancePort': 3000,
                                   'LoadBalancerPort': 80,
                                   'PolicyNames': ['CookiePolicy'],
                                   'Protocol': 'http'}],
                    'SecurityGroups': [self.get_map(
                        'Teams', self.get_ref('TeamName'), 'sg')],
                    'Subnets': self.subnets},
                'Type': 'AWS::ElasticLoadBalancing::LoadBalancer'}
            if self.memcached:
                self.add_parameter(
                    'MemcachedInstanceType', allowed=AWS.EC2_INSTANCES,
                    default=self.DEFAULT_MULTI_INSTANCE,
                    description='The memcached instance type')
                # Memcached EC2 Instance
                sections = ['preamble', 'postamble']
                userdata = self.join(*(
                    item for section in sections for item in self.join_format(
                        self.INIT[section]
                        .replace('%%RESOURCE%%', 'Memcached')
                        .replace('AppServer', 'Memcached'))))
                ENABLE = {'enabled': True, 'ensureRunning': True}
                self.template['Resources']['Memcached'] = {
                    'CreationPolicy': {'ResourceSignal': {'Timeout': 'PT5M'}},
                    'Metadata': {'AWS::CloudFormation::Init': {
                        'config': {
                            'packages': {'yum': {'memcached': []}},
                            'services': {'sysvinit': {'memcached': ENABLE}}}}},
                    'Properties': {
                        'IamInstanceProfile': self.get_ref('TeamName'),
                        'ImageId': self.get_map(
                            'AMIs', self.DEFAULT_MULTI_INSTANCE, 'ami'),
                        'InstanceType': self.get_ref('MemcachedInstanceType'),
                        'KeyName': self.get_ref('TeamName'),
                        'SecurityGroups': [self.get_ref('TeamName')],
                        'UserData': {'Fn::Base64': userdata}},
                    'Type': 'AWS::EC2::Instance'}
                self.add_ssh_output('Memcached')
        else:
            url = self.get_att('AppServer', 'PublicIp')
            self.add_ssh_output()
        self.add_output('URL', 'The URL to the rails application.',
                        self.join('http://', url))
        self.add_apps()

    def generate_passenger_ami(self):
        """Output the template used to create an up-to-date passenger AMI."""
        self.name = 'PassengerAMI'
        self.create_timeout = 'PT20M'
        self.test = False
        self.yum_packages = self.PACKAGES['passenger']
        sections = ['preamble', 'ruby', 'passenger-install', 'postamble']
        self.add_ssh_output()
        self._add_cleanup_output()
        return self.generate_template(sections, 'AppServer',
                                      self.callback_single_server)

    def generate_stack(self, app_ami, memcached, multi, puma):
        """Output the generated AWS cloudformation template.

        :param app_ami: (str) The AMI to use for the app server instance(s).
        :param memcached: (boolean) Template specifies the installation of
            memcached.
        :param multi: (boolean) Template moves the database to its own RDB
            instance, permits a variable number of app server instances, and
            distributes load to those instances via ELB.
        :param puma: (boolean) Use puma instead of passenger.

        Passenger standalone (uses nginx) will be used as the default
        application sever if puma is not specified.

        """
        # Update stack specific instance variables
        if app_ami:
            self.ami = app_ami
        self.memcached = memcached
        self.multi = multi
        self.puma = puma
        self.yum_packages = self.PACKAGES['stack']
        if not multi:
            self.yum_packages.add('mysql-server')
            if memcached:
                self.yum_packages.add('memcached')
        if not puma and not app_ami:
            self.yum_packages |= self.PACKAGES['passenger']

        name_parts = []
        # Identify stack plurality
        name_parts.append('Multi' if multi else 'Single')
        # Identify AppServer
        name_parts.append('Puma' if puma else 'Passenger')
        # Identify Addons
        if memcached:
            name_parts.append('Memcached')
        if app_ami:
            name_parts.append('-' + app_ami)
        # Create name
        self.name = ''.join(name_parts)

        sections = ['preamble', 'ruby', 'rails']
        if self.memcached:
            sections.append('memcached_install')
            if self.multi:
                sections.append('memcached_configure_multi')
            else:
                sections.append('memcached_configure_single')
        if puma:
            sections.append('puma')
        else:
            if app_ami:
                print('WARN: Ensure {0} has passenger pre-built for the '
                      'ec2-user account'.format(self.ami))
                sections.remove('ruby')  # These actions have already occured.
            else:
                sections.append('passenger-install')
            sections.append('passenger')
        sections.append('postamble')
        resource = 'AppGroup' if self.multi else 'AppServer'
        return self.generate_template(sections, resource,
                                      callback=self.callback_stack)

    def generate_template(self, sections, resource, callback=None):
        """Generate the common template functionality.

        :param callback: Call the callback function prior to returning if
            provided.

        """
        userdata = self.join(*(
            item for section in sections for item in self.join_format(
                self.INIT[section].replace('%%RESOURCE%%', resource))))
        self.template['Resources']['AppServer'] = {
            'Metadata': {'AWS::CloudFormation::Init': {
                'configSets': {'default': ['packages']},
                'packages': {
                    'packages': {'yum': {x: [] for x in self.yum_packages}}}}},
            'Properties': {'IamInstanceProfile': self.get_ref('TeamName'),
                           'ImageId': self.ami if self.ami else self.get_map(
                               'AMIs', self.get_ref('AppInstanceType'), 'ami'),
                           'InstanceType': self.get_ref('AppInstanceType'),
                           'KeyName': self.get_ref('TeamName'),
                           'UserData': {'Fn::Base64': userdata}},
            'Type': 'AWS::EC2::Instance'}
        self.add_parameter('AppInstanceType', allowed=AWS.EC2_INSTANCES,
                           default=self.DEFAULT_INSTANCE,
                           description='The AppServer instance type.')
        self.add_parameter('TeamName', allowed=sorted(self.team_map.keys()),
                           description='Your team name.')

        self.template['Mappings'] = {'AMIs': self.ami_map,
                                     'Subnets': self.subnet_map,
                                     'Teams': self.team_map}

        if callback:
            callback()
        template = json.dumps(self.template, indent=4,
                              separators=(',', ': '),
                              sort_keys=True)
        if self.test:
            self.name += 'Test'
        tmp = AWS().verify_template(template, (S3_BUCKET, self.name + '.json'))
        if tmp:
            if isinstance(self, bool):
                print(template)
                return 1
            else:
                print(tmp)
                return 0
        return 1

    def generate_tsung(self, app_ami=None):
        """Output the cloudformation template for a tsung instance.

        :param app_ami: (str) The AMI to use for the tsung EC2 instance.

        """
        if app_ami:
            self.ami = app_ami
            sections = ['preamble', 'tsung_runtime', 'postamble']
        else:
            sections = ['preamble', 'tsung', 'postamble']
        self.name = 'Tsung'
        self.create_timeout = 'PT45M'
        self.yum_packages = self.PACKAGES['tsung']
        self.add_ssh_output()
        return self.generate_template(sections, 'AppServer',
                                      self.callback_single_server)

    def generate_tsung_ami(self):
        """Output the template used to create an up-to-date tsung AMI."""
        self.name = 'TsungAMI'
        self.create_timeout = 'PT45M'
        self.test = False
        self.yum_packages = self.PACKAGES['tsung']
        sections = ['preamble', 'tsung_preamble', 'tsung', 'postamble']
        self.add_ssh_output()
        self._add_cleanup_output()
        return self.generate_template(sections, 'AppServer',
                                      self.callback_single_server)


class UTC(tzinfo):
    """Specify the UTC timezone.

    From: http://docs.python.org/release/2.4.2/lib/datetime-tzinfo.html
    """

    dst = lambda x, y: timedelta(0)
    tzname = lambda x, y: 'UTC'
    utcoffset = lambda x, y: timedelta(0)


def configure_github_team(team_name, user_names):
    """Create team and team repository and add users to the team on Github."""
    print("""About to create:
     Team: {0}
     Members: {1}\n""".format(team_name, ', '.join(user_names)))
    sys.stdout.write('Do you want to continue? [yN]: ')
    sys.stdout.flush()
    if sys.stdin.readline().strip().lower() not in ['y', 'yes', '1']:
        print('Aborting')
        return 1

    org = github_authenticate_and_fetch_org()

    team = None  # Fetch or create team
    for iteam in org.teams():
        if iteam.name == team_name:
            team = iteam
            break
    if team is None:
        team = org.create_team(team_name, permission='admin')

    repo = None  # Fetch or create repository
    for irepo in org.repositories('public'):
        if irepo.name == team_name:
            repo = irepo
            break
    if repo is None:  # Create repo and associate with the team
        repo = org.create_repository(team_name, has_wiki=False,
                                     team_id=team.id)
    elif team not in list(repo.teams()):
        print(org.add_repo(repo, team))

    # Add PT integration hook
    pt_token = get_pivotaltracker_token()
    if pt_token:
        if not repo.create_hook('pivotaltracker', {'token': pt_token}):
            print('Failed to add PT hook.')

    for user in user_names:  # Add users to the team
        print(team.invite(user))

    return 0


def generate_password(length=16):
    """Generate password containing both cases of letters and digits."""
    ALPHA = string.ascii_letters + string.digits
    selection = '0'
    while selection.isalpha() or selection.isdigit() or selection.isupper()\
            or selection.islower():
        selection = ''.join(random.choice(ALPHA) for _ in range(length))
    return selection


def get_github_token():
    """Fetch and/or load API authorization token for Github."""
    credential_file = os.path.expanduser('~/.config/scalable_github_creds')
    if os.path.isfile(credential_file):
        with open(credential_file) as fd:
            token = fd.readline().strip()
            auth_id = fd.readline().strip()
            return token, auth_id

    from github3 import authorize
    from getpass import getpass

    def two_factor_callback():
        sys.stdout.write('Two factor token: ')
        sys.stdout.flush()
        return sys.stdin.readline().strip()

    user = raw_input("Github admin username: ")
    auth = authorize(user, getpass('Password for {0}: '.format(user)),
                     ['public_repo', 'admin:org'],
                     'Scalable Internet Services Create Repo Script {0}'
                     .format(random.randint(100, 999)), 'http://example.com',
                     two_factor_callback=two_factor_callback)

    with open(credential_file, 'w') as fd:
        fd.write('{0}\n{1}\n'.format(auth.token, auth.id))
    return auth.token, auth.id


def get_pivotaltracker_token():
    """Return PivotalTracker API token if it exists."""
    token_file = os.path.expanduser('~/.config/pivotaltracker_token')
    if os.path.isfile(token_file):
        with open(token_file) as fd:
            token = fd.readline().strip()
    else:
        from getpass import getpass
        token = getpass('PivotalTracker API token: ').strip()
        if token:
            with open(token_file, 'w') as fd:
                fd.write('{0}\n'.format(token))
    return token if token else None


def github_authenticate_and_fetch_org():
    """Authenticate to github and return the desired organization handle."""
    from github3 import GitHubError, login

    while True:
        gh_token, _ = get_github_token()
        gh = login(token=gh_token)
        try:  # Test login
            return gh.membership_in(GH_ORGANIZATION).organization
        except GitHubError as exc:
            if exc.code != 401:  # Bad Credentials
                raise
            print('{0}. Try again.'.format(exc.message))
            os.unlink(os.path.expanduser('~/.config/github_creds'))


def main():
    """Enter admin.py."""
    args = docopt(__doc__)

    # Replace spaces with hyphens in team names
    if args['TEAM']:
        if isinstance(args['TEAM'], list):
            for i, item in enumerate(args['TEAM']):
                args['TEAM'][i] = item.strip().replace(' ', '-')
        else:
            args['TEAM'] = args['TEAM'].strip().replace(' ', '-')

    if args['aws']:
        for team in args['TEAM']:
            retval = AWS().configure(team)
            if retval:
                return retval
        return 0
    elif args['aws-cleanup']:
        return AWS().cleanup()
    elif args['aws-purge']:
        for team in args['TEAM']:
            retval = AWS().purge(team)
            if retval:
                return retval
    elif args['aws-update-all']:
        aws = AWS()
        for team in aws.team_to_security_group():
            retval = aws.configure(team)
            if retval:
                return retval
        return 0
    elif args['cftemplate']:
        cf = CFTemplate(test=not args['--no-test'])
        if args['passenger-ami']:
            return cf.generate_passenger_ami()
        elif args['tsung']:
            return cf.generate_tsung(app_ami=args['--app-ami'])
        elif args['tsung-ami']:
            return cf.generate_tsung_ami()
        else:
            return cf.generate_stack(app_ami=args['--app-ami'],
                                     memcached=args['--memcached'],
                                     multi=args['--multi'],
                                     puma=args['--puma'])
    elif args['cftemplate-update-all']:
        bit_pos = ['passenger', 'multi', 'memcached', 'puma']
        for i in range(2 ** len(bit_pos)):
            kwargs = {'app_ami': None}
            for bit, argument in enumerate(bit_pos):
                if i & 2 ** bit:
                    kwargs[argument] = True
                    if argument == 'passenger' and args['--passenger-ami']:
                        kwargs['app_ami'] = args['--passenger-ami']
                else:
                    kwargs[argument] = False
            cf = CFTemplate(test=not args['--no-test'])
            retval = cf.generate_stack(**kwargs)
            if retval:
                return retval
        return 0
    elif args['gh']:
        team = args['TEAM']
        team = team[0] if isinstance(team, list) else team
        return configure_github_team(team_name=team,
                                     user_names=args['USER'])
    else:
        raise Exception('Invalid state')


if __name__ == '__main__':
    sys.exit(main())
