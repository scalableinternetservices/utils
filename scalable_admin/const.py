"""Define constants used throughout the package."""

__version__ = '0.1'

AWS_CREDENTIAL_PROFILE = 'admin'
IAM_GROUP_NAME = 'scalableinternetservices'

EC2_INSTANCE_TYPES = ['t2.micro',
                      'm3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                      'c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge',
                      'r3.large', 'r3.xlarge', 'r3.2xlarge']
RDB_INSTANCE_TYPES = ['db.{0}'.format(x) for x in EC2_INSTANCE_TYPES
                      if x != 't2.micro']

# These are set to the us-east price value.
EC2_MAX_SPOT_PRICES = {
    'm3.medium':  '0.06',
    'm3.large':   '0.13',
    'm3.xlarge':  '0.26',
    'm3.2xlarge': '0.53',
    'c3.large':   '0.10',
    'c3.xlarge':  '0.21',
    'c3.2xlarge': '0.42',
    'c3.4xlarge': '0.84',
    'r3.large':   '0.17',
    'r3.xlarge':  '0.35',
    'r3.2xlarge': '0.70'}

REGION_AMIS = {'us-east-1': {'ebs': 'ami-60b6c60a',
                             'instance': 'ami-66b6c60c'},
               'us-west-2': {'ebs': 'ami-f0091d91',
                             'instance': 'ami-31342050'}}
SERVER_YUM_PACKAGES = {'passenger': {'gcc-c++', 'libcurl-devel', 'make',
                                     'openssl-devel', 'pcre-devel',
                                     'ruby21-devel'},
                       'stack': {'gcc-c++', 'git', 'make', 'mysql-devel',
                                 'ruby21-devel'},
                       'tsung': {'autoconf', 'erlang', 'gcc-c++', 'gnuplot',
                                 'perl-Template-Toolkit',
                                 'python27-matplotlib'}}


# The following globals are set via `parse_config`
GH_ORGANIZATION = None
S3_BUCKET = None
