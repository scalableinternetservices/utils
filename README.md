# Scalable Internet Services Templates

## Single Instance Templates

Both the app server, and database are located on a single EC2 instance.

* __NGINX + Passenger__ (Recommended for regular testing):  
  NGINX handles requests to port 80 and passes connections to instances of the
  app through Passenger. Multiple concurrent connections are supported.  
  https://scalableinternetservices.s3.amazonaws.com/SinglePassenger.json
* __NGINX + Passenger + memcached__:  
  Same as above, with the addition of using memcached through the `dalli` gem.
  https://scalableinternetservices.s3.amazonaws.com/SinglePassengerMemcached.json
* __Puma__:  
  Puma allows both thread-based and process-based concurrency. 
  https://scalableinternetservices.s3.amazonaws.com/SinglePuma.json
* __WEBrick__ (Use only for slow-performance testing):  
  WEBrick handles requests to port 80 directly, permitting only a single
  connection at a time.  
    * (UCLA) https://scalableinternetservices.s3.amazonaws.com/SingleWEBrick.json
    * (UCSB) https://cs290b.s3.amazonaws.com/SingleWEBrick.json


## Multiple Instance Templates

These templates launch stacks where a load balancer (ELB) distributes requests
across a cluster app server EC2 instances. Each instance in cluster is
configured to work as described above for its corresponding type.

* __NGINX + Passenger__:  
  https://scalableinternetservices.s3.amazonaws.com/MultiPassenger-ami-c5c4f9f5.json
* __NGINX + Passenger + mecmached__:  
  https://scalableinternetservices.s3.amazonaws.com/MultiPassengerMemcached-ami-c5c4f9f5.json
* __Puma__:  
  https://scalableinternetservices.s3.amazonaws.com/MultiPuma.json
* __Puma + mecmached__:  
  https://scalableinternetservices.s3.amazonaws.com/MultiPumaMemcached.json

## Other Templates

* __Tsung__:  
  This instance provides an installed version of Tsung at your disposal. You
  will need to copy/rsync over your tsung xml tests.
  https://scalableinternetservices.s3.amazonaws.com/SingleTsung-ami-f56657c5.json



## Running your own instance configuration

Add the file `.rails_initialize` to the root of your application's
repository. This should contain commands that execute as the ec2-user just
after running `rake db:migrate`. Commands that require root should be
prefixed with `sudo`. An example is provided below:

__.rails_initialize__

    rake db:seed

If you need to execute commands before installing gems, add the file `.ec2_initialize` 
to the root of your application's
repository. This should contain commands that execute as the ec2-user just
*before* running `rake db:migrate`. Commands that require root should be
prefixed with `sudo`. An example is provided below:

__.ec2_initialize__

    sudo yum install -y ImageMagick

## Configuring NGINX

NGINX is provided through _passenger-standalone_, and NGINX + Passenger is
configured to start in the cloudformation templates via the command `passenger
start`. If you would like to adjust some of the NGINX settings you can do two
things:

First, add a `Passengerfile.json` file to the root of your repository. In this
file you can specify a number of NGINX options as listed in this document:
https://www.phusionpassenger.com/documentation/Users%20guide%20Standalone.html#config_file

Second, if the few options that can be provided in `Passengerfile.json` is not
sufficient, you can provide your own nginx template. Add the following to the
json dictionary in `Passengerfile.json`:

    "nginx_config_template": "nginx.conf"

Then create the file `nginx.conf` in the root of your repository with whatever
NGINX configuration you require.

# scalable_admin.py

Provides the functionality necessary to administrate github and AWS for the
purposes of CS290 classes.


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

__Update _constant_ values in `scalable_admin.py`__:

* __GH_ORGANIZATION__: If you are using a different github organization, change
  this value to reflect your organization. This will permit the following
  commands to work as intended.

* __S3_BUCKET__: Change this value to reflect the S3 bucket where you would
  like your cloudformation templates to be stored. Teams will also be permitted
  to PUT/GET items from `S3_BUCKET/TEAMNAME/`.

## Commands

### ./scalable_admin.py aws TEAM...

Use this command to configure the AWS permissions for one ore more
teams. On first run for a team this command will create the account, outputting
the newly created credentials, and create the team's keypair file: `TEAM.pem`.

Subsequent runs can be used to make updates to a team's permissions. This is
only necessary if the permission settings have been modified in the
`scalable_admin.py` file.

### ./scalable_admin.py aws-cleanup

This command will delete stacks that are more than 8 hours old. It is useful to
run this as a cron job. The following crontab entry will run this command every
hour on the 31st minute:

    31 * * * * /path/to/the/script/utils/scalable_admin.py aws-cleanup

### ./scalable_admin.py aws-purge TEAM...

Use this command to completely remove one or more teams' permissions. This
command may fail if the AWS user for the team was manually modified through the
IAM web interface.

### ./scalable_admin.py aws-update-all

Use this command to update the permissions for all teams. The list of teams is
dynamically determined from the security group names excluding those that begin
with `default`.

### ./admin cftemplate [--no-test] [--app-ami=ami] [--multi] [--passenger] [--memcached]

This command will generate a cloud formation template usable by any of the
teams configured via `scalable_admin.py aws TEAM...`. On success, the S3 url to
the generated cloudformation template will be output. The templates will be
stored in `S3_BUCKET`.

__Note__: Regenerating templates will overwrite existing templates. Hence, by
default, template names (before the `.json` extension) are suffixed with
`Test`. When you are sure you want to replace the _production_ template, use
the `--no-test` option when generating the template.

By default all app EC2 instances use the Amazon Linux AMI as specified in
`CFTemplate.DEFAULT_AMI`. This value should be updated as Amazon releases newer
versions of the AMI. The `--app-ami` parameter can also be used to change the
AMI for a generated cloudformation template. This is primarily useful for
provding an EC2 AMI with _passenger_ precompiled.

The `--multi` flag is used to generate a cloudformation template utilizing a
load balancer to distribute requests to 1 to 8 app EC2 instances, backed by an
RDS database instance. When `--multi` is not not provided, the cloudformation
template will result in a stack that runs on a single EC2 instance.

The `--passenger` flag will result in app instances that are served via
_passenger-standalone_, rather than `rails s` (WEBrick by default). When
`--app-ami` is provided along with the `--passenger` flag, the cloudformation
template will assume passenger is precompiled in the provided AMI, otherwise,
it will be built on instance launch.

The `--memached` flag will add memcached to the stack. When used in combination
with `--multi`, memcached will run on its own instance, otherwise it'll share
the same EC2 instance with the app server and database.

### ./scalable_admin.py cftemplate tsung [--no-test]

Generate a cloudformation template to generate stacks that run the load testing
tool funkload. The `--no-test` flag works as described above.

### ./scalable_admin.py cftemplate passenger-ami

Generate a cloudformation template useful to build a passenger ami. This
template specifies an EC2 instance that precompiles passenger on launch, and
cleans up the environment so that an AMI can be immediately generated following
this document:
http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html

### ./scalable_admin.py cftemplate-update-all [--no-test] [--passenger-ami=ami]

Update all permutations of the APP-based stacks. The `--pasenger-ami` flag is
used to set the AMI for all permutations involving passenger.

### ./scalable_admin.py gh TEAM USER...

Use this command to create a git repository, if it does not already exist, and
add invite list of github USERs to the repository if they have not already been
invited. Multiple users can be specified, and should be separated by
spaces. Each USER should be the student's github account name.

Subsequent exections of the command is additive, thus it will not remove
associated/invited accounts that are not specified on the command line.
