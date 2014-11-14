# CS290 Templates

## Single Instance Templates

Both the app server, and database are located on a single EC2 instance.

* [WEBrick](https://s3-us-west-2.amazonaws.com/cf-templates-11antn0uuzgzy-us-west-2/2014318MCn-SingleWEBrick.json):
  WEBrick handles requests to port 80 directly, permitting only a single
  connection at a time.
* [NGINX +
  Passenger](https://s3-us-west-2.amazonaws.com/cf-templates-11antn0uuzgzy-us-west-2/2014318GGQ-SingleNGINXPassenger.json):
  NGINX handles requests to port 80 and passes connections to instances of the
  app through Passenger. Multiple concurrent connections are supported.


## Multiple Instance Templates

These templates launch stacks where a load balancer (ELB) distributes requests
across a cluster app server EC2 instances. Each instance in cluster is
configured to work as described above for its corresponding type.

* [WEBrick](https://s3-us-west-2.amazonaws.com/cf-templates-11antn0uuzgzy-us-west-2/20143188jS-LoadBalancedWEBrick.json)
* NGINX + Passenger: Coming soon


## Running your own instance configuration

Add the file `.ec2_initialize` to the root of your application's
repository. This should contain commands that execute as the root user just
after to running `rake db:migrate`. An example is provided below:

__.ec2_initialize__

    yum install -y ImageMagick
    rake db:seed


# cs290.py

Provides the functionality necessary to administrate github and AWS for the
purposes of CS290 classes.

## Set up

Resolve python dependencies via:

    pip install botocore docopt github3

Configure AWS credentials by creating/editing the file `~/.aws/credentials` so
that it contains an `admin` section:

    [admin]
    aws_access_key_id = ADMIN_USER_ACCESS_KEY
    aws_secret_access_key = ADMIN_USER_SECRET_ACCESS_KEY

These credentials should correspond to a user that has full permission to the
AWS API for the AWS account.

You will automatically be prompted for your github credentials the first time
you issue a `gh` command. An access token will be saved to
`~/.config/github_creds`. The github account you use should have admin rights
to the github organization.

## Commands

### ./cs290.py aws TEAM

Use this command to configure the AWS permissions for a CS290 team. On first
run for a team this will create the account, outputting the newly created
credentials, and create the team's keypair file: `TEAM.pem`.

Subsequent runs can be used to make updates to the team's permissions. This is
only necessary if the permission settings have been modified in the `cs290.py`
file.

### ./cs290.py aws-cleanup

This command will delete stacks that are more than 8 hours old. It is useful to
run this as a cron job. The following crontab entry will run this command every
hour on the 31st minute:

    31 * * * * /home/bboe/src/cs290_utils/cs290.py aws-cleanup

### ./cs290.py aws-purge TEAM

Use this command to completely undo the configuration created by `aws
TEAM`. This command may fail if the AWS user for the team was manually modified
through the IAM web interface.

### ./cs290.py gh TEAM USER...

Use this command to create a git repository, if it does not already exist, and
add invite list of github USERs to the repository if they have not already been
invited. Multiple users can be specified, and should be separated by
spaces. Each USER should be the student's github account name.

Subsequent exections of the command is additive, thus it will not remove
associated/invited accounts that are not specified on the command line.
