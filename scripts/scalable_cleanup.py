#!/usr/bin/env python3
from datetime import datetime, timedelta, tzinfo
import botocore.session
import sys


REGION = "us-west-2"


class UTC(tzinfo):
    dst = lambda x, y: timedelta(0)
    tzname = lambda x, y: "UTC"
    utcoffset = lambda x, y: timedelta(0)


NOW = datetime.now(UTC())


def stacks(cf):
    next_token = True
    while next_token:
        params = {}
        if isinstance(next_token, str):
            params["NextToken"] = next_token
        response = cf.list_stacks(**params)
        next_token = response.get("NextToken", None)
        for stack in response["StackSummaries"]:
            if stack["StackStatus"] != "DELETE_COMPLETE":
                yield stack


def is_stale_stack(stack):
    # Any non-elasticbeanstalk stack running for 5 hours
    return not stack["StackName"].startswith("awseb-e") and NOW - stack[
        "CreationTime"
    ] >= timedelta(minutes=300)


def is_delete_failed_stack(stack):
    return stack["StackStatus"] == "DELETE_FAILED"


def active_databases(rds):
    dbs = set()
    for instance in rds.describe_db_instances()["DBInstances"]:
        dbs.add(instance["DBInstanceIdentifier"])
        if instance["DBInstanceStatus"] == "available":
            pass
        elif instance["DBInstanceStatus"] not in ["backing-up", "creating", "deleting"]:
            print(f"Unhandled RDS state: {instance['DBInstanceStatus']}")
    return dbs


def delete_snapshots(rds):
    deleted = 0
    for snapshot in rds.describe_db_snapshots()["DBSnapshots"]:
        if snapshot["Status"] == "creating":
            continue
        elif snapshot["SnapshotType"] == "manual":
            rds.delete_db_snapshot(
                DBSnapshotIdentifier=snapshot["DBSnapshotIdentifier"]
            )
            deleted += 1
        elif snapshot["SnapshotType"] != "automated":
            import pprint

            pprint.pprint(snapshot)
    if deleted > 0:
        print("Deleted snapshots: {}")


def main():
    aws = botocore.session.Session(profile="scalableinternetservices-admin")

    rds = aws.create_client("rds", REGION)
    delete_snapshots(rds)
    dbs = active_databases(rds)

    cf = aws.create_client("cloudformation", REGION)
    for stack in stacks(cf):
        resources = {
            x["LogicalResourceId"]: x
            for x in cf.describe_stack_resources(StackName=stack["StackName"])[
                "StackResources"
            ]
        }
        if "AWSEBRDSDatabase" in resources:
            rds_id = resources["AWSEBRDSDatabase"]["PhysicalResourceId"]
            if rds_id in dbs:
                dbs.remove(rds_id)

        params = {}
        if is_stale_stack(stack):
            pass
        elif is_delete_failed_stack(stack):
            reason = stack["StackStatusReason"]
            index = reason.rfind("[")
            logical_ids = [x.strip() for x in reason[index + 1 : -3].split(",")]
            params["RetainResources"] = logical_ids
        else:
            continue
        print(f"Created: {NOW - stack['CreationTime']} Deleting {stack['StackName']}")
        cf.delete_stack(StackName=stack["StackName"], **params)

    # Remove orphaned databases
    for db in dbs:
        rds.delete_db_instance(DBInstanceIdentifier=db, SkipFinalSnapshot=True)

    # Terminate any deployment that hasn't been updated within an hour
    eb = aws.create_client("elasticbeanstalk", REGION)
    for deployment in eb.describe_environments()["Environments"]:
        if (
            deployment["Status"].startswith("Terminat")
            or deployment["Status"] == "Launching"
            or NOW - deployment["DateUpdated"] < timedelta(minutes=110)
        ):
            continue
        print(
            f"Last Update: {NOW - deployment['DateUpdated']} Terminating {deployment['EnvironmentName']} ({deployment['Status']})"
        )
        eb.terminate_environment(EnvironmentId=deployment["EnvironmentId"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
