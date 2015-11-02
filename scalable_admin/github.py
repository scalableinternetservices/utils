"""Provides functions that interact with github's API."""

from __future__ import print_function
from os import unlink
from os.path import expanduser, isfile
from random import randint
from sys import stdin, stdout
from .const import GH_ORGANIZATION
from .helper import get_pivotaltracker_token


def configure_github_team(team_name, user_names):
    """Create team and team repository and add users to the team on Github."""
    print("""About to create:
     Team: {0}
     Members: {1}\n""".format(team_name, ', '.join(user_names)))
    stdout.write('Do you want to continue? [yN]: ')
    stdout.flush()
    if stdin.readline().strip().lower() not in ['y', 'yes', '1']:
        print('Aborting')
        return 1

    org = github_authenticate_and_fetch_org()

    team = None  # Fetch or create team
    for iteam in org.teams():
        if iteam.name == team_name:
            team = iteam
            break
    if team is None:
        team = org.create_team(team_name, permission='admin')

    repo = None  # Fetch or create repository
    for irepo in org.repositories('public'):
        if irepo.name == team_name:
            repo = irepo
            break
    if repo is None:  # Create repo and associate with the team
        repo = org.create_repository(team_name, has_wiki=False,
                                     team_id=team.id)
    elif team not in list(repo.teams()):
        print(org.add_repo(repo, team))

    # Add PT integration hook
    pt_token = get_pivotaltracker_token()
    if pt_token:
        if not repo.create_hook('pivotaltracker', {'token': pt_token}):
            print('Failed to add PT hook.')

    for user in user_names:  # Add users to the team
        print(team.invite(user))

    return 0


def get_github_token():
    """Fetch and/or load API authorization token for Github."""
    credential_file = expanduser('~/.config/scalable_github_creds')
    if isfile(credential_file):
        with open(credential_file) as fd:
            token = fd.readline().strip()
            auth_id = fd.readline().strip()
            return token, auth_id

    from github3 import authorize
    from getpass import getpass

    def two_factor_callback():
        """Obtain input for 2FA token."""
        stdout.write('Two factor token: ')
        stdout.flush()
        return stdin.readline().strip()

    user = raw_input("Github admin username: ")
    auth = authorize(user, getpass('Password for {0}: '.format(user)),
                     ['public_repo', 'admin:org'],
                     'Scalable Internet Services Create Repo Script {0}'
                     .format(randint(100, 999)), 'http://example.com',
                     two_factor_callback=two_factor_callback)

    with open(credential_file, 'w') as fd:
        fd.write('{0}\n{1}\n'.format(auth.token, auth.id))
    return auth.token, auth.id


def github_authenticate_and_fetch_org():
    """Authenticate to github and return the desired organization handle."""
    from github3 import GitHubError, login

    while True:
        gh_token, _ = get_github_token()
        github = login(token=gh_token)
        try:  # Test login
            return github.membership_in(GH_ORGANIZATION).organization
        except GitHubError as exc:
            if exc.code != 401:  # Bad Credentials
                raise
            print('{0}. Try again.'.format(exc.message))
            unlink(expanduser('~/.config/github_creds'))
