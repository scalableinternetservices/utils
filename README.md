# CS290 Templates

## Single Instance Templates

Both the app server, and database are located on a single EC2 instance.

* [WEBrick](https://s3-us-west-2.amazonaws.com/cf-templates-11antn0uuzgzy-us-west-2/2014308gvn-CS290SingleInstance.template):
  WEBrick handles requests to port 80 directly, permitting only a single
  connection at a time.
* NGINX + Passenger (coming soon)


## Multiple Instance Templates

These templates launch stacks where a load balancer (ELB) distributes requests
across a variable number of app server EC2 instances. Each of these instances
communicates with a database RDS instance.

* [WEBrick](https://s3-us-west-2.amazonaws.com/cf-templates-11antn0uuzgzy-us-west-2/2014308xUP-CS290LoadBalanced.template):
  Each instance can handle only a single connection at a time.
