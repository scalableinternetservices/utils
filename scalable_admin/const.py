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

REGION_AMIS = {'us-east-1': {'ebs': 'ami-e3106686',
                             'instance': 'ami-65116700'},
               'us-west-2': {'ebs': 'ami-9ff7e8af',
                             'instance': 'ami-bbf7e88b'}}
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
