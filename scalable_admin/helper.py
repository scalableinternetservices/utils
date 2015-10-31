"""Defines one-off helpers used throughout the module."""

from __future__ import print_function
from datetime import timedelta, tzinfo
from json import load
from os.path import expanduser, isfile
from random import choice
from sys import stderr
from string import ascii_letters, digits
from . import AWS


class UTC(tzinfo):
    """Specify the UTC timezone.

    From: http://docs.python.org/release/2.4.2/lib/datetime-tzinfo.html
    """

    dst = lambda x, y: timedelta(0)
    tzname = lambda x, y: 'UTC'
    utcoffset = lambda x, y: timedelta(0)


def generate_password(length=16):
    """Generate password containing both cases of letters and digits."""
    characters = ascii_letters + digits
    selection = '0'
    while selection.isalpha() or selection.isdigit() or selection.isupper()\
            or selection.islower():
        selection = ''.join(choice(characters) for _ in range(length))
    return selection


def get_pivotaltracker_token():
    """Return PivotalTracker API token if it exists."""
    token_file = expanduser('~/.config/pivotaltracker_token')
    if isfile(token_file):
        with open(token_file) as fd:
            token = fd.readline().strip()
    else:
        from getpass import getpass
        token = getpass('PivotalTracker API token: ').strip()
        if token:
            with open(token_file, 'w') as fd:
                fd.write('{0}\n'.format(token))
    return token if token else None


def parse_config():
    """Parse the configuation file and set the necessary state."""
    global GH_ORGANIZATION, S3_BUCKET
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

    AWS.set_class_variables(config['aws_region'])
    GH_ORGANIZATION = config['github_organization']
    S3_BUCKET = config['s3_bucket']
