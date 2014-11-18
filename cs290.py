#!/usr/bin/env python

"""CS290 administrative utility.

Usage:
  cs290 aws TEAM
  cs290 aws-cleanup
  cs290 aws-groups
  cs290 aws-purge TEAM
  cs290 cftemplate [--no-test] [--app-ami=ami] [--multi] [--passenger] [--memcached]
  cs290 cftemplate funkload [--no-test]
  cs290 gh TEAM USER...

-h --help  show this message
"""  # flake8: noqa

from __future__ import print_function
import copy
from datetime import datetime, timedelta, tzinfo
from docopt import docopt
from pprint import pprint
from string import Formatter
import json
import os
import random
import string
import sys


class AWS(object):

    """This class handled AWS administrative tasks."""

    EC2_INSTANCES = ['t1.micro', 'm1.small']
    RDB_INSTANCES = ['db.{0}'.format(x) for x in EC2_INSTANCES]
    REGION = 'us-west-2'
    ARNCF = 'arn:aws:cloudformation:{0}:*:{{0}}'.format(REGION)
    ARNEC2 = 'arn:aws:ec2:{0}:*:{{0}}'.format(REGION)
    ARNELB = ('arn:aws:elasticloadbalancing:{0}:*:loadbalancer/{{0}}'
              .format(REGION))
    ARNRDS = 'arn:aws:rds:{0}:*:db:{{0}}'.format(REGION)
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
                           'rds:ListTagsForResource',
                           'sts:DecodeAuthorizationMessage'],
                'Effect': 'Allow', 'Resource': '*'},
               {'Action': ['ec2:Describe*'],
                'Condition': {'StringEquals': {'ec2:Region': REGION}},
                'Effect': 'Allow', 'Resource': '*'},
               {'Action': ['s3:Get*', 's3:Put*'], 'Effect': 'Allow',
                'Resource': 'arn:aws:s3:::cf-templates*{0}*'.format(REGION)}]}
    GROUP = 'cs290'
    PROFILE = 'admin'

    @staticmethod
    def op(serv, operation, debug_output=True, **kwargs):
        """Execute an AWS operation and check the response status."""
        code, data = serv[0].get_operation(operation).call(serv[1], **kwargs)
        if code.status_code == 200:
            if debug_output:
                print('Success: {0} {1}'.format(operation, kwargs))
            return data
        else:
            print(data['Error']['Message'])
            return False

    @staticmethod
    def operation_list(service_name):
        """Output the available API commands and exit."""
        pprint(service_name[0].operations)
        sys.exit(1)

    def __init__(self):
        """Initialize the AWS class."""
        import botocore.session
        self.aws = botocore.session.get_session()
        self.aws.profile = self.PROFILE
        self.ec2 = self.get_service('ec2', self.REGION)
        self.iam = self.get_service('iam', None)

    def cleanup(self):
        """Clean up old stacks and EC2 instances."""
        cf = self.get_service('cloudformation', self.REGION)
        now = datetime.now(UTC())
        for stack in self.op(cf, 'ListStacks', False)['StackSummaries']:
            if stack['StackStatus'] in {'DELETE_COMPLETE'}:
                continue
            if now - stack['CreationTime'] > timedelta(hours=8):
                self.op(cf, 'DeleteStack', StackName=stack['StackName'])

    def configure(self, team):
        """Create account and configure settings for a team.

        This method can be run subsequent times to apply team updates.
        """
        # self.operation_list(self.ec2)
        # self.operation_list(self.iam)

        # Create cs290 group if it does not exist
        self.op(self.iam, 'CreateGroup', GroupName=self.GROUP)
        self.op(self.iam, 'PutGroupPolicy', GroupName=self.GROUP,
                PolicyName=self.GROUP, PolicyDocument=json.dumps(self.POLICY))

        # Configure user account / password / access keys / keypair
        if self.op(self.iam, 'CreateUser', UserName=team):
            self.op(self.iam, 'CreateLoginProfile', UserName=team,
                    Password=generate_password())
            data = self.op(self.iam, 'CreateAccessKey', UserName=team)
            if data:
                print('AccessKey: {0}'
                      .format(data['AccessKey']['AccessKeyId']))
                print('SecretKey: {0}'
                      .format(data['AccessKey']['SecretAccessKey']))
            data = self.op(self.ec2, 'CreateKeyPair', KeyName=team)
            if data:
                filename = '{0}.pem'.format(team)
                with open(filename, 'w') as fd:
                    os.chmod(filename, 0600)
                    fd.write(data['KeyMaterial'])
                print('Keypair saved as: {0}'.format(filename))
        self.op(self.iam, 'AddUserToGroup', GroupName=self.GROUP,
                UserName=team)

        # Configure security group
        self.op(self.ec2, 'CreateSecurityGroup', GroupName=team,
                Description=team)
        for port in [22, 80, 443]:  # Open standard ports to all addresses.
            # These are run one at a time so that existance of one doesn't
            # prevent the creation of the others.
            rule = {'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            self.op(self.ec2, 'AuthorizeSecurityGroupIngress',
                    GroupName=team, IpPermissions=[rule])
        # Permit all instances in the SecurityGroup to talk to each other
        self.op(self.ec2, 'AuthorizeSecurityGroupIngress', GroupName=team,
                IpPermissions=[
                    {'IpProtocol': '-1', 'FromPort': 0, 'ToPort': 65535,
                     'UserIdGroupPairs': [{'GroupName': team}]}])

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
             'Resource': AWS.ARNELB.format('{}*'.format(team))})
        policy['Statement'].append(
            {'Action': ['rds:DeleteDBInstance', 'rds:RebootDBInstance'],
             'Effect': 'Allow',
             'Resource': AWS.ARNRDS.format('{0}*'.format(team))})
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
        # Allow full access to cs290/TEAM in S3
        policy['Statement'].extend([
            {'Action': '*', 'Effect': 'Allow',
             'Resource': 'arn:aws:s3:::cs290/{0}/*'.format(team)},
            {'Action': 's3:ListBucket', 'Effect': 'Allow',
             'Resource': 'arn:aws:s3:::cs290'}])
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
             'Resource': AWS.ARNRDS.format('{0}*'.format(team))})
        self.op(self.iam, 'PutUserPolicy', UserName=team,
                PolicyName=team, PolicyDocument=json.dumps(policy))

        return 0

    def get_service(self, service_name, endpoint_name):
        """Return a tuple containing the service and associated endpoint."""
        service = self.aws.get_service(service_name)
        return service, service.get_endpoint(endpoint_name)

    def list_security_groups(self):
        """Output the teams and their security groups.

        This function is useful for updating the CFTemplate.TEAM2SG value.
        """
        retval = self.op(self.ec2, 'DescribeSecurityGroups')
        pprint({x['GroupName']: {'sg': x['GroupId']} for x in
                retval['SecurityGroups']})

    def purge(self, team):
        """Remove all settings pertaining to `team`."""
        self.op(self.iam, 'DeleteLoginProfile', UserName=team)
        self.op(self.iam, 'DeleteUserPolicy', UserName=team,
                PolicyName=team)
        resp = self.op(self.iam, 'ListAccessKeys', UserName=team)
        if resp:
            for keydata in resp['AccessKeyMetadata']:
                self.op(self.iam, 'DeleteAccessKey', UserName=team,
                        AccessKeyId=keydata['AccessKeyId'])

        self.op(self.iam, 'RemoveUserFromGroup', GroupName=self.GROUP,
                UserName=team)
        self.op(self.iam, 'DeleteUser', UserName=team)
        self.op(self.ec2, 'DeleteKeyPair', KeyName=team)
        self.op(self.ec2, 'DeleteSecurityGroup', GroupName=team)
        return 0

    def verify_template(self, template, upload=None):
        """Verify a cloudformation template.

        :param upload: When provided, it should be a tuple containing the
            bucket and key to upload the template to. If the template is valid,
            it will be uploaded to this s3 bucket, and the URL to the template
            in S3 will be returned. Note that this URL is not publicly
            accessible, but it will work for CloudFormation Stack generation.
        """
        cf = self.get_service('cloudformation', self.REGION)
        valid = bool(self.op(cf, 'ValidateTemplate', TemplateBody=template,
                             debug_output=False))
        if not valid or upload is None:
            return valid
        # Upload to s3
        bucket, key = upload
        s3 = self.get_service('s3', None)
        retval = self.op(s3, 'PutObject', Bucket=bucket, Key=key,
                         Body=template, acl='public-read', debug_output=False)
        if not retval:
            return retval
        return '{host}/{bucket}/{key}'.format(
            host=s3[1].host, bucket=bucket, key=key)


class CFTemplate(object):

    """Generate CS290 Cloudformation templates."""

    DEFAULT_AMI = 'ami-55a7ea65'
    # The following strings are python-format strings, however, the values
    # between brackets will be replaced with `{'Ref': 'value'}`. Make sure to
    # escape intended brackets: '{' => '{{', '}' => '}}'
    INIT = {'preamble': """#!/bin/bash -v
yum update -y aws-cfn-bootstrap
# Helper function
function error_exit {{
    /opt/aws/bin/cfn-signal -e 1 -r "$1" --stack {AWS::StackName} \
      --resource %%RESOURCE%% --region {AWS::Region}
    exit 1
}}
# Run cfn-init (see AWS::CloudFormation::Init)
/opt/aws/bin/cfn-init -s {AWS::StackName} -r AppServer \
  --region {AWS::Region} || error_exit 'Failed to run cfn-init'
""",
            'rails': """# Update alternatives
alternatives --set ruby /usr/bin/ruby2.1
alternatives --set gem /usr/bin/gem2.1
# Install bundler only after the alternatives have been set.
gem install bundle
# Change to the app directory
cd /home/ec2-user/app

# Add environment variables to ec2-user's .bashrc
echo "export RAILS_ENV=production" >> ../.bashrc
echo "export SECRET_KEY_BASE=b801783afb83bb8e614b32ccf6c05c855a927116d92062a75\
c6ffa61d58c58e62f13eb60cf1a31922c44b7e6a3e8f1809934a93llask938bl" >> ../.bashrc
echo "export PATH=/usr/local/bin:\$PATH" >> ../.bashrc

# Redirect port 80 to port 3000 (ec2-user cannot bind port 80)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3000

# Don't require tty to run sudo (the remaining commands)
sed -i 's/requiretty/!requiretty/' /etc/sudoers

# Run the remaining commands as the ec2-user in the app directory
sudo -u ec2-user bash -lc "bundle install --without test development"\
 || error_exit 'Failed to install bundle'
# Create the database and run the migrations (try up to 10x)
loop=10
while [ $loop -gt 0 ]; do
  sudo -u ec2-user bash -lc "rake db:create db:migrate"
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
if [ -f .ec2_initialize ]; then
    sudo -u ec2-user bash -l .ec2_initialize\
     || error_exit 'Failed to run .ec2_initialize'
fi
# Fix multi_json gem version (>1.7.8 has issues precompiling assets)
echo -e "\ngem 'multi_json', '1.7.8'" >> Gemfile
sudo -u ec2-user bash -lc "bundle update multi_json"\
 || error_exit 'Failed to update multi_json'
# Generate static assets
sudo -u ec2-user bash -lc "rake assets:precompile"\
 || error_exit 'Failed to precompile static assets'
""",
            'webrick': """# Configure the app to serve static assets
sed -i 's/serve_static_assets = false/serve_static_assets = true/'\
 config/environments/production.rb
# Start up WEBrick (or whatever server is installed)
sudo -u ec2-user bash -lc "rails server -d"\
 || error_exit 'Failed to start rails server'
""",
            'passenger': """# Start passenger
sudo -u ec2-user bash -lc "passenger start -d --no-compile-runtime"\
 || error_exit 'Failed to start passenger'
""",
            'passenger-install': """# Install Passenger
gem install passenger || error_exit 'Failed to install passenger gem'
# Add swap space needed to build passenger if running on t1.micro
if [ "{AppInstanceType}" == "t1.micro" ]; then
  dd if=/dev/zero of=/swap bs=1M count=512\
   || error_exit 'Failed to create swap file'
  mkswap /swap || error_exit 'Failed to mkswap'
  swapon /swap || error_exit 'Failed to enable swap'
fi
# Build and install passenger
sudo -u ec2-user bash -lc "passenger start --runtime-check-only"\
 || error_exit 'Failed to build or install passenger'
if [ "{AppInstanceType}" == "t1.micro" ]; then
  swapoff /swap || error_exit 'Failed to disable swap'
  rm /swap || error_exit 'Failed to delete /swap'
fi
""",
            'postamble': """# All is well so signal success
/opt/aws/bin/cfn-signal -e 0 --stack {AWS::StackName} --resource %%RESOURCE%% \
  --region {AWS::Region}
"""}
    INSTANCES = ['t1.micro', 'm1.small', 'm1.medium', 'm1.large', 'm1.xlarge',
                 'm2.xlarge', 'm2.2xlarge', 'm2.4xlarge', 'm3.xlarge',
                 'm3.2xlarge']
    # Update this value periodically from the `cs290 aws-groups` output.
    TEAM_MAP = {'BaconWindshield': {'sg': 'sg-ab3052ce'},
                'Compete': {'sg': 'sg-d33052b6'},
                'Gradr': {'sg': 'sg-b53052d0'},
                'LaPlaya': {'sg': 'sg-dd3052b8'},
                'Lab-App': {'sg': 'sg-763c5213'},
                'Motley-Crew': {'sg': 'sg-fa97fa9f'},
                'Suppr': {'sg': 'sg-b13052d4'},
                'Team-Hytta': {'sg': 'sg-1297fa77'},
                'Upvid': {'sg': 'sg-bd3052d8'},
                'Xup': {'sg': 'sg-a03052c5'},
                'labapp': {'sg': 'sg-661f7203'},
                'picShare': {'sg': 'sg-db3052be'}}
    TEMPLATE = {'AWSTemplateFormatVersion': '2010-09-09',
                'Outputs': {},
                'Parameters': {},
                'Resources': {}}
    # Update this bucket on a per-class-account basis
    TEMPLATE_BUCKET = 'cs290'

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
                retval.append({'Ref': item[1]})
                if item[2]:  # Correct the string when '::' is used
                    retval[-1]['Ref'] += ':' + item[2]
        return retval

    def __init__(self, test):
        """Initialize the CFTemplate class.

        :param test: When true, append 'Test' to generated template name.
        """
        self.ami = self.DEFAULT_AMI
        self.create_timeout = 'PT5M'
        self.template = copy.deepcopy(self.TEMPLATE)
        self.test = test
        self.yum_packages = []

    def add_apps(self):
        """Update either the EC2 instance or autoscaling group."""
        app = {'sources': {'/home/ec2-user/app': self.join(
            'https://github.com/scalableinternetservices/',
            self.get_ref('TeamName'), '/tarball/', self.get_ref('Branch'))}}
        if not self.multi:
            app['services'] = {'sysvinit': {'mysqld': {'enabled': True,
                                                       'ensureRunning': True}}}
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
            conf['Type'] = 'AWS::AutoScaling::LaunchConfiguration'
        else:
            conf['CreationPolicy'] = {
                'ResourceSignal': {'Timeout': self.create_timeout}}

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

    def callback_stack(self):
        """Update the template parameters for the stack."""
        self.add_parameter('Branch', default='master',
                           description='The git branch to deploy.')

        if self.multi:
            url = self.get_att('LoadBalancer', 'DNSName')
            self.add_parameter('AppInstances', 'Number', default=2,
                               description=('The number of AppServer instances'
                                            ' to launch.'),
                               maxv=8, minv=1)
            self.add_parameter('DBInstanceType', allowed=['db.' + x for x in
                                                          self.INSTANCES],
                               default='db.t1.micro',
                               description='The Database instance type.',
                               error_msg=('Must be a valid db.t1, db.m1, or '
                                          'db.m2 EC2 instance type.'))
            self.template['Mappings'] = {'Teams': self.TEAM_MAP}
            self.template['Resources']['AppGroup'] = {
                'CreationPolicy': {'ResourceSignal': {
                    'Count': self.get_ref('AppInstances'),
                    'Timeout': self.create_timeout}},
                'Properties': {
                    'AvailabilityZones': {'Fn::GetAZs': ''},
                    'LaunchConfigurationName':
                    self.get_ref('AppServer'),
                    'LoadBalancerNames': [self.get_ref('LoadBalancer')],
                    'MaxSize': self.get_ref('AppInstances'),
                    'MinSize': self.get_ref('AppInstances')},
                'Type': 'AWS::AutoScaling::AutoScalingGroup'}
            self.template['Resources']['Database'] = {
                'Properties': {
                    'AllocatedStorage': 5,
                    'BackupRetentionPeriod': 0,
                    'DBInstanceClass': self.get_ref('DBInstanceType'),
                    'DBInstanceIdentifier': self.get_ref('AWS::StackName'),
                    'DBName': 'rails_app',
                    'Engine': 'mysql',
                    'MasterUsername': 'root',
                    'MasterUserPassword': 'password',
                    'VPCSecurityGroups': [self.get_map(
                        'Teams', self.get_ref('TeamName'), 'sg')]},
                'Type': 'AWS::RDS::DBInstance'}
            self.template['Resources']['LoadBalancer'] = {
                'Properties': {
                    'AvailabilityZones': {'Fn::GetAZs': ''},
                    'LBCookieStickinessPolicy': [
                        {'PolicyName': 'CookiePolicy',
                         'CookieExpirationPeriod': 30}],
                    'LoadBalancerName': self.get_ref('AWS::StackName'),
                    'Listeners': [{'InstancePort': 80, 'LoadBalancerPort': 80,
                                   'PolicyNames': ['CookiePolicy'],
                                   'Protocol': 'http'}]},
                'Type': 'AWS::ElasticLoadBalancing::LoadBalancer'}
        else:
            url = self.get_att('AppServer', 'PublicDnsName')
        self.add_output('URL', 'The URL to the rails application.',
                        self.join('http://', url))
        self.add_apps()

    def generate_funkload(self):
        """Output the cloudformation template for a funkload instance."""
        self.name = 'FunkloadTest' if self.test else 'FunkLoad'
        sections = ['preamble', 'postamble']
        return self.generate_template(sections, 'AppServer',
                                      callback=self.callback_funkload)

    def generate_stack(self, app_ami, memcached, multi, passenger):
        """Output the generated AWS cloudformation template.

        :param app_ami: (str) The AMI to use for the app server instance(s).
        :param memcached: (boolean) Template specifies a separate memcached
            instance.
        :param multi: (boolean) Template moves the database to its own RDB
            instance, permits a variable number of app server instances, and
            distributes load to those instances via ELB.
        :param passenger: (boolean) Use passenger standalone (nginx) as the
            entry-point into each app server rather than `rails s` (WEBrick by
            default).
        """
        # Update stack specific instance variables
        if app_ami:
            self.ami = app_ami
        self.memcached = memcached
        self.multi = multi
        self.passenger = passenger
        self.yum_packages.extend(['gcc-c++', 'git', 'make', 'mysql-devel',
                                  'ruby21-devel'])
        if not multi:
            self.yum_packages.append('mysql-server')
        if passenger:
            self.yum_packages.extend(['libcurl-devel', 'pcre-devel'])

        name_parts = []
        name_parts.append('Multi' if multi else 'Single')
        name_parts.append('Passenger' if passenger else 'WEBrick')
        if memcached:
            name_parts.append('Memcached')
        if app_ami:
            name_parts.append(app_ami)
        if self.test:
            name_parts.append('Test')
        self.name = ''.join(name_parts)
        if passenger and not app_ami:
            self.create_timeout = 'PT20M'

        sections = ['preamble', 'rails']
        if passenger:
            if app_ami:
                print('WARN: Ensure {0} has passenger pre-built for the '
                      'ec2-user account'.format(self.ami))
            else:  # Template installs passenger (this is slow)
                sections.append('passenger-install')
            sections.append('passenger')
        else:
            sections.append('webrick')
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
                'packages': {
                    'packages':{'yum': {x: [] for x in self.yum_packages}}}}},
            'Properties': {'ImageId': self.ami,
                           'InstanceType': self.get_ref('AppInstanceType'),
                           'KeyName': self.get_ref('TeamName'),
                           'SecurityGroups': [self.get_ref('TeamName')],
                           'UserData': {'Fn::Base64': userdata}},
            'Type': 'AWS::EC2::Instance'}
        self.add_parameter('AppInstanceType', allowed=self.INSTANCES,
                           default='t1.micro',
                           description='The AppServer instance type.',
                           error_msg=('Must be a valid t1, m1, or m2 EC2 '
                                      'instance type.'))
        self.add_parameter('TeamName', allowed=self.TEAM_MAP.keys(),
                           description='Your CS290 team name.',
                           error_msg=('Must exactly match your team name '
                                      'as shown in your Github URL.'))
        if callback:
            callback()
        template = json.dumps(self.template, indent=4,
                              separators=(',', ': '),
                              sort_keys=True)
        tmp = AWS().verify_template(template, (self.TEMPLATE_BUCKET,
                                               self.name + '.json'))
        if tmp:
            if isinstance(self, bool):
                print(template)
            else:
                print(tmp)


class UTC(tzinfo):

    """Specify the UTC timezone.

    From: http://docs.python.org/release/2.4.2/lib/datetime-tzinfo.html
    """

    dst = lambda x, y: timedelta(0)
    tzname = lambda x, y: 'UTC'
    utcoffset = lambda x, y: timedelta(0)


def configure_github_team(team_name, user_names):
    """Create team and team repository and add users to the team on Github."""
    from github3 import login
    print("""About to create:
     Team: {0}
     Members: {1}\n""".format(team_name, ', '.join(user_names)))
    sys.stdout.write('Do you want to continue? [yN]: ')
    sys.stdout.flush()
    if sys.stdin.readline().strip().lower() not in ['y', 'yes', '1']:
        print('Aborting')
        return 1

    gh_token, _ = get_github_token()
    gh = login(token=gh_token)
    org = gh.membership_in('scalableinternetservices').organization

    team = None  # Fetch or create team
    for iteam in org.iter_teams():
        if iteam.name == team_name:
            team = iteam
            break
    if team is None:
        team = org.create_team(team_name, permission='push')

    repo = None  # Fetch or create repository
    for irepo in org.iter_repos('public'):
        if irepo.name == team_name:
            repo = irepo
            break
    if repo is None:  # Create repo and associate with the team
        repo = org.create_repo(team_name, has_wiki=False,
                               has_downloads=False, team_id=team.id)
    elif team not in list(repo.iter_teams()):
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
    """Generate a random password containing letters and digits."""
    ALPHA = string.ascii_letters + string.digits
    return ''.join(random.choice(ALPHA) for _ in range(length))


def get_github_token():
    """Fetch and/or load API authorization token for Github."""
    credential_file = os.path.expanduser('~/.config/github_creds')
    if os.path.isfile(credential_file):
        with open(credential_file) as fd:
            token = fd.readline().strip()
            auth_id = fd.readline().strip()
            return token, auth_id

    from github3 import authorize
    from getpass import getuser, getpass

    def two_factor_callback():
        sys.stdout.write('Two factor token: ')
        sys.stdout.flush()
        return sys.stdin.readline().strip()

    user = getuser()
    auth = authorize(user, getpass('Password for {0}: '.format(user)),
                     ['public_repo'], 'CS290 Create Repo Script',
                     'http://example.com',
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


def main():
    """Enter cs290.py."""
    args = docopt(__doc__)

    if args['TEAM']:
        args['TEAM'] = args['TEAM'].replace(' ', '-')

    if args['aws']:
        return AWS().configure(args['TEAM'])
    elif args['aws-cleanup']:
        return AWS().cleanup()
    elif args['aws-groups']:
        return AWS().list_security_groups()
    elif args['aws-purge']:
        return AWS().purge(args['TEAM'])
    elif args['cftemplate']:
        cf = CFTemplate(test=not args['--no-test'])
        if args['funkload']:
            return cf.generate_funkload()
        else:
            return cf.generate_stack(app_ami=args['--app-ami'],
                                     memcached=args['--memcached'],
                                     multi=args['--multi'],
                                     passenger=args['--passenger'])
    elif args['gh']:
        return configure_github_team(team_name=args['TEAM'],
                                     user_names=args['USER'])
    else:
        raise Exception('Invalid state')


if __name__ == '__main__':
    sys.exit(main())
