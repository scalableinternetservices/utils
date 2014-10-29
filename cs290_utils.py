#!/usr/bin/env python

"""Usage:
  cs290_utils aws TEAM
  cs290_utils gh TEAM USER...

-h --help  show this message
"""

from __future__ import print_function
from docopt import docopt
import copy
import json
import os
import random
import string
import sys


EC2_REGION = 'us-west-2'
AWS_POLICY = {'Statement':
              [{'Action': ['ec2:CreateTags', 'ec2:DescribeAvailabilityZones',
                           'ec2:DescribeImages', 'ec2:DescribeInstances',
                           'ec2:DescribeKeyPairs',
                           'ec2:DescribeSecurityGroups', 'ec2:DescribeSubnets',
                           'ec2:DescribeTags', 'ec2:DescribeVPCs'],
                'Condition': {'StringEquals': {'ec2:Region': EC2_REGION}},
                'Effect': 'Allow', 'Resource': '*'}]}


def configure_aws(team_name, full_access_profile='admin'):
    def get_service(service_name, endpoint_name):
        """Return a tuple containing the service and associated endpoint."""
        service = aws.get_service(service_name)
        return service, service.get_endpoint(endpoint_name)

    def op(serv, operation, **kwargs):
        """Execute an AWS operation and check the response status."""
        code, data = serv[0].get_operation(operation).call(serv[1], **kwargs)
        if code.status_code == 200:
            print('Success: {0} {1}'.format(operation, kwargs))
            return data
        else:
            print(data['Error']['Message'])
            return False

    def operation_list(service_name):
        """Output the available API commands and exit."""
        import pprint
        pprint.pprint(service_name[0].operations)
        sys.exit(1)

    import botocore.session
    aws = botocore.session.get_session()
    aws.profile = full_access_profile
    ec2 = get_service('ec2', EC2_REGION)
    iam = get_service('iam', None)

    # operation_list(ec2)
    # operation_list(iam)

    # Configure user account / password / access keys / keypair
    if op(iam, 'CreateUser', UserName=team_name):
        op(iam, 'CreateLoginProfile', UserName=team_name,
           Password=generate_password())
        data = op(iam, 'CreateAccessKey', UserName=team_name)
        if data:
            print('AccessKey: {0}'.format(data['AccessKey']['AccessKeyId']))
            print('SecretKey: {0}'
                  .format(data['AccessKey']['SecretAccessKey']))
        data = op(ec2, 'CreateKeyPair', KeyName=team_name)
        if data:
            with open('{0}.pem'.format(team_name), 'w') as fd:
                fd.write(data['KeyMaterial'])
            print('Keypair saved as: {0}.pem'.format(team_name))

    # Configure security group
    op(ec2, 'CreateSecurityGroup', GroupName=team_name, Description=team_name)
    for port in [22, 80, 443]:  # Open standard ports to all addresses.
        # These are run one at a time so that existance of one doesn't prevent
        # the creation of the others.
        rule = {'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        op(ec2, 'AuthorizeSecurityGroupIngress', GroupName=team_name,
           IpPermissions=[rule])
    # Permit all instances in the SecurityGroup to talk to each other
    op(ec2, 'AuthorizeSecurityGroupIngress', GroupName=team_name,
       IpPermissions=[{'IpProtocol': '-1', 'FromPort': 0, 'ToPort': 65535,
                       'UserIdGroupPairs': [{'GroupName': team_name}]}])

    # Configure the user's AWS policy.
    policy = copy.deepcopy(AWS_POLICY)
    policy['Statement'].append(
        {'Action': ['ec2:RebootInstances', 'ec2:StartInstances',
                    'ec2:StopInstances', 'ec2:TerminateInstances'],
         'Condition': {'StringEquals': {'ec2:ResourceTag/team': team_name}},
         'Effect': 'Allow', 'Resource': '*'})
    op(iam, 'PutUserPolicy', UserName=team_name, PolicyName=team_name,
       PolicyDocument=json.dumps(policy))

    return 0


def configure_github_team(team_name, user_names):
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
    ALPHA = string.ascii_letters + string.digits
    return ''.join(random.choice(ALPHA) for _ in range(length))


def get_github_token():
    """Fetch and/or load API authorization token for GITHUB."""
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
    args = docopt(__doc__)

    if args['aws']:
        return configure_aws(team_name=args['TEAM'])
    elif args['gh']:
        return configure_github_team(team_name=args['TEAM'],
                                     user_names=args['USER'])
    else:
        raise Exception('Invalid state')


if __name__ == '__main__':
    sys.exit(main())
