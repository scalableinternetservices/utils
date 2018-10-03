"""Defines one-off helpers used throughout the module."""
from __future__ import print_function
from json import load
from os.path import expanduser, isfile
from random import choice
from sys import stderr
from string import ascii_letters, digits
from . import const


def generate_password(length=16):
    """Generate password containing both cases of letters and digits."""
    characters = ascii_letters + digits
    selection = '0'
    while selection.isalpha() or selection.isdigit() or selection.isupper()\
            or selection.islower():
        selection = ''.join(choice(characters) for _ in range(length))
    return selection


def parse_config(aws):
    """Parse the configuation file and set the necessary state."""
    config_path = expanduser('~/.config/scalable_admin.json')
    if not isfile(config_path):
        stderr.write('{0} does not exist.\n'.format(config_path))
        exit(1)

    with open(config_path) as fp:
        config = load(fp)

    error = False
    for key in ['aws_region', 'github_organization', 's3_bucket']:
        if key not in config:
            stderr.write('The key {0} does not exist in {1}\n'.format(
                key, config_path))
            error = True
    if error:
        exit(1)

    aws.set_class_variables(config['aws_region'])
    const.GH_ARCHIVE_ORGANIZATION = config['github_archive_organization']
    const.GH_ORGANIZATION = config['github_organization']
    const.S3_BUCKET = config['s3_bucket']
