"""Provides functions that interact with github's API."""

from __future__ import print_function
from os import unlink
from os.path import isfile
from random import randint
from sys import stdin, stdout
from . import const


def archive_projects(config):
    """Set archive flag on all projects in archive repo."""
    organization = github_authenticate_with_org(config["github_archive_organization"])
    for repository in organization.repositories():
        if not repository.archived:
            repository.edit(repository.name, archived=True)


def configure_github_team(config, team_name, user_names):
    """Create team and team repository and add users to the team on Github."""
    print(
        f"""About to create:
     Team: {team_name}
     Members: {', '.join(user_names)}\n"""
    )
    stdout.write("Do you want to continue? [yN]: ")
    stdout.flush()
    if stdin.readline().strip().lower() not in ["y", "yes", "1"]:
        print("Aborting")
        return 1

    org = github_authenticate_with_org(config["github_organization"])

    team = None  # Fetch or create team
    for iteam in org.teams():
        if iteam.name == team_name:
            team = iteam
            break
    if team is None:
        team = org.create_team(team_name, permission="admin")

    repo = None  # Fetch or create repository
    for irepo in org.repositories("public"):
        if irepo.name == team_name:
            repo = irepo
            break
    if repo is None:  # Create repo and associate with the team
        repo = org.create_repository(team_name, has_wiki=False, team_id=team.id)
    elif team not in list(repo.teams()):
        print(org.add_repo(repo, team))

    for user in user_names:  # Add users to the team
        print(team.invite(user))

    return 0


def get_github_token():
    """Fetch and/or load API authorization token for Github."""
    if isfile(const.GH_CREDENTIAL_FILE):
        with open(const.GH_CREDENTIAL_FILE) as file_descriptor:
            token = file_descriptor.readline().strip()
            auth_id = file_descriptor.readline().strip()
            return token, auth_id

    from github3 import authorize
    from getpass import getpass

    def two_factor_callback():
        """Obtain input for 2FA token."""
        stdout.write("Two factor token: ")
        stdout.flush()
        return stdin.readline().strip()

    user = input("Github admin username: ")
    auth = authorize(
        user,
        getpass(f"Password for {user}: "),
        ["public_repo", "admin:org"],
        f"Scalable Internet Services Create Repo Script {randint(100, 999)}",
        "http://example.com",
        two_factor_callback=two_factor_callback,
    )

    with open(const.GH_CREDENTIAL_FILE, "w") as file_descriptor:
        file_descriptor.write(f"{auth.token}\n{auth.id}\n")
    return auth.token, auth.id


def github_authenticate_with_org(organization):
    """Authenticate to github and return the desired organization handle."""
    from github3 import GitHubError, login

    while True:
        gh_token, _ = get_github_token()
        github = login(token=gh_token)
        try:  # Test login
            return github.membership_in(organization).organization
        except GitHubError as exc:
            if exc.code != 401:  # Bad Credentials
                raise
            print(f"{exc.message}. Try again.")

            if isfile(const.GH_CREDENTIAL_FILE):
                unlink(const.GH_CREDENTIAL_FILE)
