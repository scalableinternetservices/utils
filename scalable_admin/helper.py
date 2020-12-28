"""Defines one-off helpers used throughout the module."""
import json
import random
import os.path
import string
import sys


CONFIG_PATH = os.path.expanduser("~/.config/scalable_admin.json")
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


def parse_config():
    """Parse the configuation file and set the necessary state."""
    if not os.path.isfile(CONFIG_PATH):
        sys.stderr.write(f"{CONFIG_PATH} does not exist.\n")
        sys.exit(1)

    with open(CONFIG_PATH) as fp:
        config = json.load(fp)

    error = False
    for key in REQUIRED_CONFIG_KEYS:
        if key not in config:
            sys.stderr.write(f"The key {key} does not exist in {CONFIG_PATH}\n")
            error = True
    if error:
        sys.exit(1)

    return config


def update_config(**update_values):
    config = parse_config()
    config.update(**update_values)
    with open(CONFIG_PATH, "w") as fp:
        json.dump(config, fp)
    return config
