"""Define constants used throughout the package."""
from os.path import expanduser

__version__ = "0.1"

AWS_CREDENTIAL_PROFILE = "admin"
GH_CREDENTIAL_FILE = expanduser("~/.config/github_creds")
IAM_GROUP_NAME = "scalableinternetservices"

EC2_INSTANCE_TYPES = [
    "t2.micro",
    "m3.medium",
    "m4.large",
    "m4.xlarge",
    "m4.2xlarge",
    "m4.4xlarge",
    "c5.large",
    "c5.xlarge",
    "c5.2xlarge",
    "c5.4xlarge",
    "r4.large",
    "r4.xlarge",
    "r4.2xlarge",
]
RDB_INSTANCE_TYPES = ["db.{0}".format(x) for x in EC2_INSTANCE_TYPES if x != "t2.micro"]

# These are set to the us-east price value.
EC2_MAX_SPOT_PRICES = {
    "m3.medium": "0.06",
    "m4.large": "0.10",
    "m4.xlarge": "0.20",
    "m4.2xlarge": "0.40",
    "m4.4xlarge": "0.80",
    "c5.large": "0.08",
    "c5.xlarge": "0.17",
    "c5.2xlarge": "0.34",
    "c5.4xlarge": "0.68",
    "r4.large": "0.13",
    "r4.xlarge": "0.26",
    "r4.2xlarge": "0.53",
}

SERVER_YUM_PACKAGES = {
    "passenger": {"libcurl-devel", "openssl-devel", "pcre-devel"},
    "stack": {"gcc-c++", "git", "make", "mysql-devel", "ruby22-devel"},
    "tsung": {},
}


# The following globals are set via `parse_config`
GH_ARCHIVE_ORGANIZATION = None
GH_ORGANIZATION = None
S3_BUCKET = None
