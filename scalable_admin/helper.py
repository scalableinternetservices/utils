"""Defines one-off helpers used throughout the module."""
import json
import random
import os.path
import string
import sys


REQUIRED_CONFIG_KEYS = {
    "aws_account_alias",
    "aws_account_id",
    "aws_iam_group_name",
    "aws_region",
    "github_archive_organization",
    "github_organization",
}


def generate_password(length=16):
    """Generate password containing both cases of letters and digits."""
    characters = string.ascii_letters + string.digits
    selection = "0"
    while (
        selection.isalpha()
        or selection.isdigit()
        or selection.isupper()
        or selection.islower()
    ):
        selection = "".join(random.choice(characters) for _ in range(length))
    return selection


def parse_config(aws):
    """Parse the configuation file and set the necessary state."""
    config_path = os.path.expanduser("~/.config/scalable_admin.json")
    if not os.path.isfile(config_path):
        sys.stderr.write(f"{config_path} does not exist.\n")
        sys.exit(1)

    with open(config_path) as fp:
        config = json.load(fp)

    error = False
    for key in REQUIRED_CONFIG_KEYS:
        if key not in config:
            sys.stderr.write(f"The key {key} does not exist in {config_path}\n")
            error = True
    if error:
        sys.exit(1)

    return config
