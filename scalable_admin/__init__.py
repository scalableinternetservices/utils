"""Scalable Admin is a helps administrate teams' access to github and aws."""
from __future__ import print_function
from os import chmod
from sys import stderr
import json

import botocore.exceptions
import botocore.session

from . import const
from .helper import generate_password


class AWS(object):
    """This class handles AWS administrative tasks."""

    AWS_ACCOUNT_ID = "671946291905"
    REGION = None

    @staticmethod
    def exec(method, debug_output=True, **kwargs):
        """Execute an AWS operation and check the response status."""
        try:
            response = method(**kwargs)
        except botocore.exceptions.ClientError as exc:
            stderr.write(exc.response["Error"]["Message"])
            stderr.write("\n")
            return False
        if debug_output:
            stderr.write("Success: {0} {1}\n".format(method.__name__, kwargs))
        return response

    def __init__(self):
        """Initialize the AWS class."""
        self.aws = botocore.session.Session(profile=const.AWS_CREDENTIAL_PROFILE)
        self.ec2 = self.aws.create_client("ec2", self.REGION)
        self.iam = self.aws.create_client("iam", None)

    def configure(self, team):
        """Create account and configure settings for a team.

        This method can be run subsequent times to apply team updates.
        """
        # Create team IAM group if it does not exist
        self.exec(self.iam.create_group, GroupName=team)
        self.exec(
            self.iam.put_group_policy,
            GroupName=team,
            PolicyName=team,
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Action": [
                                "lambda:AddPermission",
                                "lambda:CreateFunction",
                                "lambda:DeleteFunction",
                                "lambda:GetFunction",
                                "lambda:GetPolicy",
                                "lambda:InvokeFunction",
                                "lambda:ListVersionsByFunction",
                                "lambda:UpdateFunctionCode",
                            ],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:lambda:{self.REGION}:{self.AWS_ACCOUNT_ID}:function:{team}",
                        },
                        {
                            "Action": ["logs:DescribeLogStreams"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:logs:{self.REGION}:{self.AWS_ACCOUNT_ID}:log-group:/aws/lambda/{team}:log-stream:",
                        },
                        {
                            "Action": ["logs:GetLogEvents"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:logs:{self.REGION}:{self.AWS_ACCOUNT_ID}:log-group:/aws/lambda/{team}:log-stream:*",
                        },
                    ]
                }
            ),
        )

        # Create class IAM group if it does not exist
        self.exec(self.iam.create_group, GroupName=const.IAM_GROUP_NAME)
        self.exec(
            self.iam.put_group_policy,
            GroupName=const.IAM_GROUP_NAME,
            PolicyName=const.IAM_GROUP_NAME,
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Action": [
                                "apigateway:DELETE",
                                "apigateway:GET",
                                "apigateway:POST",
                                "apigateway:PUT",
                            ],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:apigateway:{self.REGION}::/restapis*",
                        },
                        {
                            "Action": ["apigateway:GET"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:apigateway:{self.REGION}::/*",
                        },
                        {
                            "Action": ["iam:PassRole"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:iam::{self.AWS_ACCOUNT_ID}:role/CS291Lambda",
                        },
                        {
                            "Action": [
                                "lambda:GetAccountSettings",
                                "lambda:ListFunctions",
                            ],
                            "Effect": "Allow",
                            "Resource": "*",
                        },
                        {
                            "Action": ["logs:DescribeLogGroups"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:logs:{self.REGION}:{self.AWS_ACCOUNT_ID}:log-group::log-stream:",
                        },
                    ]
                }
            ),
        )

        # Configure user account / password / access keys / keypair
        if self.exec(self.iam.create_user, UserName=team):
            password = generate_password()
            self.exec(self.iam.create_login_profile, UserName=team, Password=password)
            data = self.exec(self.iam.create_access_key, UserName=team)
            if data:
                filename = "{0}_web_credentials.txt".format(team)
                with open(filename, "w") as fp:
                    fp.write(
                        "     URL: https://bboe-ucsb.signin.aws.amazon.com/console\n"
                    )
                    fp.write("   alias: bboe-ucsb\n")
                    fp.write("Username: {0}\n".format(team))
                    fp.write("Password: {0}\n".format(password))
                filename = "{0}_api_credentials.txt".format(team)
                with open(filename, "w") as fp:
                    fp.write("[default]\n")
                    fp.write(
                        f"aws_access_key_id={format(data['AccessKey']['AccessKeyId'])}\n"
                    )
                    fp.write(
                        f"aws_secret_access_key={data['AccessKey']['SecretAccessKey']}\n\n"
                    )
                    fp.write("[cs291]\n")
                    fp.write(
                        f"aws_access_key_id={format(data['AccessKey']['AccessKeyId'])}\n"
                    )
                    fp.write(
                        f"aws_secret_access_key={data['AccessKey']['SecretAccessKey']}\n"
                    )
            data = self.exec(self.ec2.create_key_pair, KeyName=team)
            if data:
                filename = "{0}.pem".format(team)
                with open(filename, "w") as file_descriptor:
                    chmod(filename, 0o600)
                    file_descriptor.write(data["KeyMaterial"])

        self.exec(self.iam.add_user_to_group, GroupName=team, UserName=team)
        self.exec(
            self.iam.add_user_to_group, GroupName=const.IAM_GROUP_NAME, UserName=team
        )

        return 0

    def purge(self, team):
        """Remove all settings pertaining to `team`."""
        # Remove access permissions
        self.exec(self.iam.delete_login_profile, UserName=team)
        resp = self.exec(self.iam.list_access_keys, UserName=team)
        if resp:
            for keydata in resp["AccessKeyMetadata"]:
                self.exec(
                    self.iam.delete_access_key,
                    UserName=team,
                    AccessKeyId=keydata["AccessKeyId"],
                )
        self.exec(self.ec2.delete_key_pair, KeyName=team)
        # Remove user from groups
        group_response = self.exec(self.iam.list_groups_for_user, UserName=team)
        groups = group_response["Groups"] if group_response else []
        for group in groups:
            group_name = group["GroupName"]
            self.exec(
                self.iam.remove_user_from_group, GroupName=group_name, UserName=team
            )
            if not self.exec(self.iam.get_group, GroupName=group_name)["Users"]:
                # Delete group
                self.exec(
                    self.iam.delete_group_policy,
                    GroupName=group_name,
                    PolicyName=group_name,
                )
                self.exec(self.iam.delete_group, GroupName=group_name)
        # Delete user
        self.exec(self.iam.delete_user, UserName=team)
        return 0
