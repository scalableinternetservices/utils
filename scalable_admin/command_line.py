"""Scalable Internet Services administrative utility.

Usage:
  scalable_admin aws TEAM...
  scalable_admin aws-purge TEAM...
  scalable_admin aws-update-all
  scalable_admin github TEAM USER...
  scalable_admin github-archive (TEAM|--all)

-h --help  show this message
"""
from docopt import docopt

from .github import archive_project, archive_projects, configure_github_team
from .helper import parse_config
from . import AWS


def clean_team_names(args):
    """Replace spaces and underscores with hyphens in team names."""
    if args["TEAM"]:
        for i, item in enumerate(args["TEAM"]):
            item = item.strip().replace(" ", "-")
            args["TEAM"][i] = item.replace("_", "-")


def cmd_aws(args, config):
    """Handle the aws command."""
    aws = AWS(config)
    for team in args["TEAM"]:
        retval = aws.configure(team)
        if retval:
            return retval
    return 0


def cmd_aws_purge(args, config):
    """Handle the aws-purge command."""
    aws = AWS(config)
    for team in args["TEAM"]:
        retval = aws.purge(team)
        if retval:
            return retval
    return 0


def cmd_aws_update_all(_, config):
    """Handle the aws-update-all command."""
    aws = AWS(config)
    for team in aws.teams():
        retval = aws.configure(team)
        if retval:
            return retval
    return 0


def cmd_github(args, config):
    """Handle the github command."""
    return configure_github_team(
        config=config, team_name=args["TEAM"][0], user_names=args["USER"]
    )


def cmd_github_archive(args, config):
    if args["--all"]:
        return archive_projects(config=config)
    else:
        assert len(args["TEAM"]) == 1
        return archive_project(config=config, name=args["TEAM"][0])


def main():
    """Provide the entrance point for the scalable_admin command."""
    args = docopt(__doc__)

    config = parse_config()
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
            return commands[command_name](args, config=config)

    raise Exception("Unexpected command.")
