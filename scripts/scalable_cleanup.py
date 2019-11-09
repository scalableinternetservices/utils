#!/usr/bin/env python3
from datetime import datetime, timedelta, tzinfo
import botocore.session
import pprint
import sys


REGION = "us-west-2"


class UTC(tzinfo):
    dst = lambda x, y: timedelta(0)
    tzname = lambda x, y: "UTC"
    utcoffset = lambda x, y: timedelta(0)


NOW = datetime.now(UTC())


def orphaned_databases(rds):
    dbs = set()
    for instance in rds.describe_db_instances()["DBInstances"]:
        if instance["DBName"] == "ebdb":
            continue
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
            pprint.pprint(snapshot)
    if deleted > 0:
        print(f"Deleted snapshots: {deleted}")


def main():
    aws = botocore.session.Session(profile="scalableinternetservices-admin")

    rds = aws.create_client("rds", REGION)
    delete_snapshots(rds)
    dbs = active_databases(rds)

    # Remove orphaned databases
    for db in dbs:
        print(f"Deleting database: {db}")
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
