"""Scalable Admin is a helps administrate teams' access to github and aws."""

from __future__ import print_function
from copy import deepcopy
from datetime import datetime, timedelta
from pkg_resources import resource_stream
from os import chmod
from pprint import pprint
from string import Formatter
from sys import stderr
import botocore.exceptions
import botocore.session
import json
from . import const
from .helper import (UTC, generate_password)


class AWS(object):
    """This class handles AWS administrative tasks."""

    @staticmethod
    def op(method, debug_output=True, **kwargs):
        """Execute an AWS operation and check the response status."""
        try:
            response = method(**kwargs)
        except botocore.exceptions.ClientError as exc:
            stderr.write(exc.message)
            stderr.write('\n')
            return False
        except:
            raise
        if debug_output:
            stderr.write('Success: {0} {1}\n'.format(method.__name__, kwargs))
        return response

    @staticmethod
    def operation_list(service_name):
        """Output the available API commands and exit."""
        pprint(service_name[0].operations)
        exit(1)

    @classmethod
    def set_class_variables(cls, region):
        """Set class-based variables that depend on the passed in region."""
        cls.region = region
        cls.arncf = 'arn:aws:cloudformation:{0}:*:{{0}}'.format(cls.region)
        cls.arnec2 = 'arn:aws:ec2:{0}:*:{{0}}'.format(cls.region)
        cls.arnelb = ('arn:aws:elasticloadbalancing:{0}:*:loadbalancer/{{0}}'
                      .format(cls.region))
        cls.arnrds = 'arn:aws:rds:{0}:*:db:{{0}}'.format(cls.region)
        cls.arnrdssub = 'arn:aws:rds:{0}:*:subgrp:{{0}}'.format(cls.region)
        cls.policy = {
            'Statement':
            [{'Action': ['autoscaling:*',  # No fine grained permissions
                         'cloudformation:CreateUploadBucket',
                         'cloudformation:Describe*',
                         'cloudformation:Get*',
                         'cloudformation:ListStack*',
                         'cloudformation:ValidateTemplate',
                         'cloudwatch:DescribeAlarms',
                         'cloudwatch:GetMetricStatistics',
                         'elasticloadbalancing:Describe*',
                         'iam:ListServerCertificates',
                         'rds:Describe*',
                         'rds:ListTagsForResource',
                         'sts:DecodeAuthorizationMessage'],
              'Effect': 'Allow', 'Resource': '*'},
             {'Action': ['ec2:Describe*'],
              'Condition': {'StringEquals': {'ec2:Region': cls.region}},
              'Effect': 'Allow', 'Resource': '*'},
             {'Action': ['s3:Get*', 's3:Put*'], 'Effect': 'Allow',
              'Resource': ('arn:aws:s3:::cf-templates*{0}*'
                           .format(cls.region))}]}

    def __init__(self):
        """Initialize the AWS class."""
        self.aws = botocore.session.Session(
            profile=const.AWS_CREDENTIAL_PROFILE)
        self.ec2 = self.aws.create_client('ec2', self.region)
        self.iam = self.aws.create_client('iam', None)
        self.rds = self.aws.create_client('rds', self.region)

    def az_to_subnet(self):
        """Return a mapping of availability zone to their subnet."""
        vpc = self.op(self.ec2.describe_vpcs)['Vpcs'][0]
        subnets = self.op(self.ec2.describe_subnets, Filters=[
            {'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])['Subnets']
        return {x['AvailabilityZone']: {'subnet': x['SubnetId']}
                for x in subnets}

    def cleanup(self):
        """Clean up old stacks and EC2 instances."""
        cloud = self.aws.create_client('cloudformation', self.region)
        now = datetime.now(UTC())
        for stack in self.op(cloud.list_stacks, False)['StackSummaries']:
            if stack['StackStatus'] in {'DELETE_COMPLETE'}:
                continue
            if now - stack['CreationTime'] > timedelta(minutes=290):
                self.op(cloud.delete_stack, StackName=stack['StackName'])

    def configure(self, team):
        """Create account and configure settings for a team.

        This method can be run subsequent times to apply team updates.
        """
        s3_statement = [
            {'Action': '*', 'Effect': 'Allow',
             'Resource': 'arn:aws:s3:::{0}/{1}/*'.format(
                 const.S3_BUCKET, team)},
            {'Action': 's3:ListBucket', 'Effect': 'Allow',
             'Condition': {'StringLike': {'s3:prefix': '{0}/*'.format(team)}},
             'Resource': 'arn:aws:s3:::{0}'.format(const.S3_BUCKET)}]

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
        self.op(self.iam.create_group, GroupName=const.IAM_GROUP_NAME)
        self.op(self.iam.put_group_policy, GroupName=const.IAM_GROUP_NAME,
                PolicyName=const.IAM_GROUP_NAME,
                PolicyDocument=json.dumps(self.policy))

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
                    chmod(filename, 0o600)
                    fd.write(data['KeyMaterial'])
                print('Keypair saved as: {0}'.format(filename))
        self.op(self.iam.add_user_to_group, GroupName=const.IAM_GROUP_NAME,
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
             'Resource': AWS.arncf.format('stack/{0}*'.format(team))})
        policy['Statement'].append(
            {'Action': ['ec2:RebootInstances', 'ec2:StartInstances',
                        'ec2:StopInstances', 'ec2:TerminateInstances'],
             'Condition': {
                 'StringLike': {
                     'ec2:ResourceTag/aws:cloudformation:stack-name':
                     '{0}*'.format(team)}},
             'Effect': 'Allow', 'Resource': AWS.arnec2.format('instance/*')})
        policy['Statement'].append(
            {'Action': 'elasticloadbalancing:*',
             'Effect': 'Allow',
             'Resource': AWS.arnelb.format('{0}*'.format(team))})
        policy['Statement'].append(
            {'Action': ['rds:DeleteDBInstance', 'rds:RebootDBInstance'],
             'Effect': 'Allow',
             'Resource': AWS.arnrds.format('{0}*'.format(team).lower())})
        # Creation policies
        policy['Statement'].append(
            {'Action': 'ec2:RunInstances',
             'Effect': 'Allow',
             'Resource': [AWS.arnec2.format('image/*'),
                          AWS.arnec2.format('key-pair/{0}'.format(team)),
                          AWS.arnec2.format('network-interface/*'),
                          AWS.arnec2.format('security-group/*'),
                          AWS.arnec2.format('subnet/*'),
                          AWS.arnec2.format('volume/*')]})
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
                 'StringLike': {'ec2:InstanceType': const.EC2_INSTANCE_TYPES}},
             'Effect': 'Allow',
             'Resource': AWS.arnec2.format('instance/*')})
        # Filter the RDS instance types that are allowed to be started
        policy['Statement'].append(
            {'Action': ['rds:CreateDBInstance', 'rds:ModifyDBInstance'],
             'Condition': {
                 'Bool': {'rds:MultiAz': 'false'},
                 'NumericEquals': {'rds:Piops': '0', 'rds:StorageSize': '5'},
                 'StringEquals': {'rds:DatabaseEngine': 'mysql'},
                 'StringLike': {
                     'rds:DatabaseClass': const.RDB_INSTANCE_TYPES}},
             'Effect': 'Allow',
             'Resource': [AWS.arnrds.format('{0}*'.format(team).lower()),
                          AWS.arnrdssub.format('{0}'.format(team).lower())]})

        # Create and associate TEAM group (can have longer policy lists)
        self.op(self.iam.create_group, GroupName=team)
        self.op(self.iam.put_group_policy, GroupName=team, PolicyName=team,
                PolicyDocument=json.dumps(policy))
        self.op(self.iam.add_user_to_group, GroupName=team, UserName=team)
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
        self.op(self.iam.delete_instance_profile, InstanceProfileName=team)
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
        cloud = self.aws.create_client('cloudformation', self.region)
        valid = bool(self.op(cloud.validate_template, TemplateBody=template,
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

    ENABLE_PARAM = {'enabled': True, 'ensureRunning': True}
    TEMPLATE = {'AWSTemplateFormatVersion': '2010-09-09',
                'Outputs': {},
                'Parameters': {},
                'Resources': {}}
    _subnet_map = None

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
    def join_format(format_string):
        """Convert formatted strings into the cloudformation join format."""
        retval = []
        for item in Formatter().parse(format_string):
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

    @staticmethod
    def multi_instance_filter(instances):
        """Filter out t2 instance types."""
        return [x for x in instances if not x.startswith('t2')]

    @staticmethod
    def tsung_instance_filter(instances):
        """Filter out anything but m3 instance types."""
        return [x for x in instances if x.startswith('m3')]

    @classmethod
    def segment(cls, name):
        """Return the contents of the segment named `name`.sh."""
        return resource_stream(__name__, 'segments/{0}.sh'.format(name)).read()

    @classmethod
    def subnet_map(cls):
        """Return a mapping of AZ to subnet."""
        if cls._subnet_map is None:
            cls._subnet_map = AWS().az_to_subnet()
        return cls._subnet_map

    def __init__(self, test):
        """Initialize the CFTemplate class.

        :param test: When true, append 'Test' to generated template name.
        """
        self.ami = self.memcached = self.multi = self.name = self.puma = None
        self.create_timeout = 'PT10M'
        self.template = deepcopy(self.TEMPLATE)
        self.test = test
        self.yum_packages = None
        self._team_map = None

    @property
    def ami_map(self):
        """Return a mapping of instance type to their AMI."""
        def ami_type(instance_type):
            """Return the AMI for a particular instance type."""
            return {'t2.micro': 'ebs'}.get(instance_type, 'instance')

        return {x: {'ami': const.REGION_AMIS[AWS.region][ami_type(x)]} for x in
                const.EC2_INSTANCE_TYPES}

    @property
    def default_subnet(self):
        """Return the first subnet for the VPC."""
        return sorted(self.subnets)[0]

    @property
    def spot_pricing_map(self):
        """Return a mapping of instance type to spot price."""
        return {key: {'price': value} for (key, value) in
                const.EC2_MAX_SPOT_PRICES.items()}

    @property
    def subnets(self):
        """Return a list of VPC subnets."""
        return [x['subnet'] for x in self.subnet_map().values()]

    @property
    def team_map(self):
        """Return a mapping of teams to their security group."""
        if self._team_map is None:
            self._team_map = AWS().team_to_security_group()
        return self._team_map

    def add_apps(self):
        """Update either the EC2 instance or autoscaling group."""
        app = {'sources': {'/home/ec2-user/app': self.join(
            'https://github.com/{0}/'.format(const.GH_ORGANIZATION),
            self.get_ref('TeamName'), '/tarball/', self.get_ref('Branch'))}}
        if not self.multi:
            app['services'] = {'sysvinit': {'mysqld': self.ENABLE_PARAM}}
            if self.memcached:
                app['services']['sysvinit']['memcached'] = self.ENABLE_PARAM
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
            conf['Properties']['SpotPrice'] = self.get_map(
                'SpotPrices', self.get_ref('AppInstanceType'), 'price')
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
                        self.join('ssh -i ', self.get_ref('TeamName'),
                                  '.pem ec2-user@',
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
            instances = self.multi_instance_filter(const.EC2_INSTANCE_TYPES)
            url = self.get_att('LoadBalancer', 'DNSName')
            self.add_parameter('AppInstances', allowed=range(1, 9), default=2,
                               description=('The number of AppServer instances'
                                            ' to launch.'))
            self.add_parameter('DBInstanceType',
                               allowed=const.RDB_INSTANCE_TYPES,
                               default=const.RDB_INSTANCE_TYPES[0],
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
                self.add_parameter('MemcachedInstanceType',
                                   allowed=instances, default=instances[0],
                                   description='The memcached instance type.')
                # Memcached EC2 Instance
                sections = ['preamble', 'postamble']
                userdata = self.join(*(
                    item for section in sections for item in self.join_format(
                        self.segment(section)
                        .replace('%%RESOURCE%%', 'Memcached')
                        .replace('AppServer', 'Memcached'))))
                self.template['Resources']['Memcached'] = {
                    'CreationPolicy': {'ResourceSignal': {'Timeout': 'PT5M'}},
                    'Metadata': {'AWS::CloudFormation::Init': {
                        'config': {
                            'packages': {'yum': {'memcached': []}},
                            'services': {'sysvinit':
                                         {'memcached': self.ENABLE_PARAM}}}}},
                    'Properties': {
                        'IamInstanceProfile': self.get_ref('TeamName'),
                        'ImageId': self.get_map(
                            'AMIs', self.get_ref('MemcachedInstanceType'),
                            'ami'),
                        'InstanceType': self.get_ref('MemcachedInstanceType'),
                        'KeyName': self.get_ref('TeamName'),
                        'SecurityGroupIds': [self.get_map(
                            'Teams', self.get_ref('TeamName'), 'sg')],
                        'SubnetId': self.default_subnet,
                        'UserData': {'Fn::Base64': userdata}},
                    'Type': 'AWS::EC2::Instance'}
                self.add_ssh_output('Memcached')
        else:
            url = self.get_att('AppServer', 'PublicIp')
            self.add_ssh_output()
        self.add_output('URL', 'The URL to the rails application.',
                        self.join('http://', url))
        self.add_apps()

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
        self.yum_packages = const.SERVER_YUM_PACKAGES['stack']
        if not multi:
            self.yum_packages.add('mysql-server')
            if memcached:
                self.yum_packages.add('memcached')
        if not (puma or app_ami):
            self.yum_packages |= const.SERVER_YUM_PACKAGES['passenger']

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
            sections.append('passenger')
        sections.append('postamble')

        resource = 'AppGroup' if self.multi else 'AppServer'
        instance_filter = self.multi_instance_filter if self.multi else None
        return self.generate_template(sections, resource,
                                      callback=self.callback_stack,
                                      instance_filter=instance_filter)

    def generate_template(self, sections, resource, callback=None,
                          instance_filter=None):
        """Generate the common template functionality.

        :param callback: Call the callback function prior to returning if
            provided.

        """
        userdata = self.join(*(
            item for section in sections for item in self.join_format(
                self.segment(section).replace('%%RESOURCE%%', resource))))

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

        if instance_filter:
            instances = instance_filter(const.EC2_INSTANCE_TYPES)
        else:
            instances = const.EC2_INSTANCE_TYPES
        self.add_parameter('AppInstanceType', allowed=instances,
                           default=instances[0],
                           description='The AppServer instance type.')

        self.add_parameter('TeamName', allowed=sorted(self.team_map.keys()),
                           description='Your team name.')

        self.template['Mappings'] = {'AMIs': self.ami_map,
                                     'SpotPrices': self.spot_pricing_map,
                                     'Subnets': self.subnet_map(),
                                     'Teams': self.team_map}

        if callback:
            callback()
        template = json.dumps(self.template, indent=4,
                              separators=(',', ': '),
                              sort_keys=True)
        if self.test:
            self.name += 'Test'
        tmp = AWS().verify_template(template,
                                    (const.S3_BUCKET, self.name + '.json'))
        if tmp:
            if isinstance(self, bool):
                print(template)
                return 1
            else:
                print(tmp)
                return 0
        return 1

    def generate_tsung(self):
        """Output the cloudformation template for a Tsung instance."""
        sections = ['preamble', 'tsung', 'postamble']
        self.name = 'Tsung'
        self.yum_packages = const.SERVER_YUM_PACKAGES['tsung']
        self.add_ssh_output()
        url = self.get_att('AppServer', 'PublicIp')
        self.add_output('URL', 'The URL to the rails application.',
                        self.join('http://', url))

        return self.generate_template(sections, 'AppServer',
                                      self.callback_single_server,
                                      self.tsung_instance_filter)
