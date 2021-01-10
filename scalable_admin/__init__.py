"""Scalable Admin is a helps administrate teams' access to github and aws."""
import os
import json
import sys

import botocore.exceptions
import botocore.session

from .helper import generate_password


class AWS:
    """This class handles AWS administrative tasks."""

    @staticmethod
    def exec(method, debug_output=True, **kwargs):
        """Execute an AWS operation and check the response status."""
        try:
            response = method(**kwargs)
        except botocore.exceptions.ClientError as exc:
            sys.stderr.write(exc.response["Error"]["Message"])
            sys.stderr.write("\n")
            return False
        if debug_output:
            sys.stderr.write(f"Success: {method.__name__} {kwargs}\n")
        return response

    def __init__(self, config):
        """Initialize the AWS class."""
        self.aws = botocore.session.Session(profile="scalableinternetservices-admin")
        self.config = config
        self.ec2 = self.aws.create_client("ec2", config["aws_region"])
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
                            "Resource": f"arn:aws:lambda:{self.config['aws_region']}:{self.config['aws_account_id']}:function:{team}",
                        },
                        {
                            "Action": ["logs:DescribeLogStreams"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:logs:{self.config['aws_region']}:{self.config['aws_account_id']}:log-group:/aws/lambda/{team}:log-stream:",
                        },
                        {
                            "Action": ["logs:GetLogEvents"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:logs:{self.config['aws_region']}:{self.config['aws_account_id']}:log-group:/aws/lambda/{team}:log-stream:*",
                        },
                    ]
                }
            ),
        )

        # Create class IAM group if it does not exist
        self.exec(self.iam.create_group, GroupName=self.config["aws_iam_group_name"])
        self.exec(
            self.iam.put_group_policy,
            GroupName=self.config["aws_iam_group_name"],
            PolicyName=self.config["aws_iam_group_name"],
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
                            "Resource": f"arn:aws:apigateway:{self.config['aws_region']}::/restapis*",
                        },
                        {
                            "Action": ["apigateway:GET"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:apigateway:{self.config['aws_region']}::/*",
                        },
                        {
                            "Action": ["iam:PassRole"],
                            "Effect": "Allow",
                            "Resource": f"arn:aws:iam::{self.config['aws_account_id']}:role/ScalableInternetServicesLambda",
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
                            "Resource": f"arn:aws:logs:{self.config['aws_region']}:{self.config['aws_account_id']}:log-group::log-stream:",
                        },
                    ]
                }
            ),
        )

        # Attach AWSElasticBeanstalkFullAccess to class group
        self.exec(
            self.iam.attach_group_policy,
            GroupName=self.config["aws_iam_group_name"],
            PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkFullAccess",
        )

        # Configure user account / password / access keys / keypair
        if self.exec(self.iam.create_user, UserName=team):
            password = generate_password()
            self.exec(self.iam.create_login_profile, UserName=team, Password=password)
            data = self.exec(self.iam.create_access_key, UserName=team)
            if data:
                filename = f"{team}_web_credentials.txt"
                with open(filename, "w") as fp:
                    fp.write(
                        f"     URL: https://{self.config['aws_account_alias']}.signin.aws.amazon.com/console\n"
                    )
                    fp.write(f"   alias: {self.config['aws_account_alias']}\n")
                    fp.write(f"Username: {team}\n")
                    fp.write(f"Password: {password}\n")
                filename = f"{team}_api_credentials.txt"
                with open(filename, "w") as fp:
                    fp.write("[default]\n")
                    fp.write(
                        f"aws_access_key_id={format(data['AccessKey']['AccessKeyId'])}\n"
                    )
                    fp.write(
                        f"aws_secret_access_key={data['AccessKey']['SecretAccessKey']}\n\n"
                    )
                    fp.write("[scalableinternetservices]\n")
                    fp.write(
                        f"aws_access_key_id={format(data['AccessKey']['AccessKeyId'])}\n"
                    )
                    fp.write(
                        f"aws_secret_access_key={data['AccessKey']['SecretAccessKey']}\n"
                    )
            data = self.exec(self.ec2.create_key_pair, KeyName=team)
            if data:
                filename = f"{team}.pem"
                with open(filename, "w") as file_descriptor:
                    os.chmod(filename, 0o600)
                    file_descriptor.write(data["KeyMaterial"])

        self.exec(self.iam.add_user_to_group, GroupName=team, UserName=team)
        self.exec(
            self.iam.add_user_to_group,
            GroupName=self.config["aws_iam_group_name"],
            UserName=team,
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

    def teams(self):
        for user in self.exec(
            self.iam.get_group, GroupName=self.config["aws_iam_group_name"]
        )["Users"]:
            yield user["UserName"]
