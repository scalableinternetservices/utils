"""Scalable Internet Services administrative utility.

Usage:
  scalable_admin aws TEAM...
  scalable_admin aws-purge TEAM...
  scalable_admin aws-update-all
  scalable_admin github TEAM USER...
  scalable_admin github-archive

-h --help  show this message
"""
from __future__ import print_function
from docopt import docopt
from . import AWS
from .github import archive_projects, configure_github_team
from .helper import parse_config


def clean_team_names(args):
    """Replace spaces and underscores with hyphens in team names."""
    if args["TEAM"]:
        if isinstance(args["TEAM"], list):
            for i, item in enumerate(args["TEAM"]):
                item = item.strip().replace(" ", "-")
                args["TEAM"][i] = item.replace("_", "-")
        else:
            args["TEAM"] = args["TEAM"].strip().replace(" ", "-")
            args["TEAM"] = args["TEAM"].replace("_", "-")


def cmd_aws(args):
    """Handle the aws command."""
    for team in args["TEAM"]:
        retval = AWS().configure(team)
        if retval:
            return retval
    return 0


def cmd_aws_purge(args):
    """Handle the aws-purge command."""
    for team in args["TEAM"]:
        retval = AWS().purge(team)
        if retval:
            return retval
    return 0


def cmd_aws_update_all(_):
    """Handle the aws-update-all command."""
    aws = AWS()
    for team in aws.team_to_security_group():
        retval = aws.configure(team)
        if retval:
            return retval
    return 0


def cmd_github(args):
    """Handle the github command."""
    team = args["TEAM"]
    team = team[0] if isinstance(team, list) else team
    return configure_github_team(team_name=team, user_names=args["USER"])


def cmd_github_archive(_):
    return archive_projects()


def main():
    """Provide the entrance point for the scalable_admin command."""
    args = docopt(__doc__)

    parse_config(AWS)
    clean_team_names(args)

    commands = {
        "aws": cmd_aws,
        "aws-purge": cmd_aws_purge,
        "aws-update-all": cmd_aws_update_all,
        "github": cmd_github,
        "github-archive": cmd_github_archive,
    }

    for command_name in commands:
        if args[command_name]:
            return commands[command_name](args)

    raise Exception("Unexpected command.")
