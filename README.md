# Scalable Internet Services Utility Script

# scalable_admin.py

Provides the functionality necessary to administrate github and AWS for the
purposes of Scalable Internet Services classes.


## Set up

__Resolve python dependencies via__:

    python setup.py install

__Configure AWS credentials by creating/editing the file `~/.aws/credentials`
so that it contains an `admin` section__:

    [admin]
    aws_access_key_id = ADMIN_USER_ACCESS_KEY
    aws_secret_access_key = ADMIN_USER_SECRET_ACCESS_KEY

These credentials should correspond to a user that has full permission to the
AWS API for the AWS account.

You will automatically be prompted for your github credentials the first time
you issue a `gh` command. An access token will be saved to
`~/.config/github_creds`. The github account you use should have admin rights
to the github organization.

__Create/update `$(HOME)/.config/scalable_admin.json`__

The file has three keys that need to be set:

* __aws_region__: Set this value to permit students access to that single AWS
  region.

* __github_organization__: Set this value to reflect your github organization.

* __s3_bucket__: Set this value to reflect the S3 bucket where you would like
  your cloudformation templates to be stored. Teams will also be permitted to
  PUT/GET items from `s3_bucket/TEAMNAME/`.

Below is an example of the contents of the json file:

```json
{
"aws_region": "us-west-2",
"github_organization": "scalableinternetservices",
"s3_bucket": "cs291"
}
```

## Commands

### scalable_admin aws TEAM...

Use this command to configure the AWS permissions for one ore more
teams. On first run for a team this command will create the account, outputting
the newly created credentials, and create the team's keypair file: `TEAM.pem`.

Subsequent runs can be used to make updates to a team's permissions. This is
only necessary if the permission settings have been modified in the
`scalable_admin.py` file.

### scalable_admin aws-purge TEAM...

Use this command to completely remove one or more teams' permissions. This
command may fail if the AWS user for the team was manually modified through the
IAM web interface.

### scalable_admin aws-update-all

Use this command to update the permissions for all teams. The list of teams is
dynamically determined from the security group names excluding those that begin
with `default`.

### scalable_admin tsung-template [--no-test]

Generate a cloudformation template to generate stacks that run the load testing
tool tsung. The `--no-test` flag works as described above.

### scalable_admin github TEAM USER...

Use this command to create a git repository, if it does not already exist, and
add invite list of github USERs to the repository if they have not already been
invited. Multiple users can be specified, and should be separated by
spaces. Each USER should be the student's github account name.

Subsequent exections of the command is additive, thus it will not remove
associated/invited accounts that are not specified on the command line.
