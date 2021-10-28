"""Provides functions that interact with github's API."""
import io
import json
import zipfile
from random import randint
from sys import stdin, stdout

from github3 import GitHubError
from github3.github import GitHub
from github3.repos import Repository

from . import const
from .helper import update_config


def _get_repository(organization, repository_name):
    for repository in organization.repositories("public"):
        if repository.name.lower() == repository_name.lower():
            return repository
    return None


def _get_team(organization, team_name):
    for team in organization.teams():
        if team.name.lower() == team_name.lower():
            return team
    return None


def _transfer_repository(repository, destination):
    url = repository._build_url("transfer", base_url=repository._api)
    repository._json(repository._post(url, data={"new_owner": destination}), 202)


def archive_project(config, name):
    archive_org = github_authenticate_with_org(
        config["github_archive_organization"],
        access_token=config.get("github_access_token"),
    )
    archive_repo = _get_repository(archive_org, name)
    if archive_repo is not None:
        print(f"Repo {name} already exists in organization {archive_org.login}.")
        return 1

    live_org = github_authenticate_with_org(
        config["github_organization"], access_token=config.get("github_access_token")
    )
    repo = _get_repository(live_org, name)
    if repo is None:
        print(f"Repo {name} does not exist in organization {live_org.login}.")
        return 1

    for team in repo.teams():
        for member in team.members():
            print(f"Adding {member} to repository.")
            repo.add_collaborator(member)
        if len(list(team.repositories())) == 1:
            print(f"Deleting team {team.name}.")
            team.delete()

    print("Transferring repository.")
    _transfer_repository(repo, archive_org.login)
    repository = _get_repository(archive_org, name)
    print("Archiving repository.")
    repository.edit(repository.name, archived=True)


def archive_projects(config):
    """Set archive flag on all projects in archive repo."""
    repository = config["github_archive_organization"]
    organization = github_authenticate_with_org(
        repository, access_token=config.get("github_access_token")
    )
    print(f"Setting archive bit on all repos in {repository}.")
    for repository in organization.repositories():
        if not repository.archived:
            repository.edit(repository.name, archived=True)


def cleanup(config):
    """Remove users from organization who are not associated with a team."""
    organization = github_authenticate_with_org(
        config["github_organization"], access_token=config.get("github_access_token")
    )
    members_with_team = set()
    for team in organization.teams():
        for member in team.members():
            members_with_team.add(member)

    for member in organization.members():
        if member not in members_with_team:
            print(f"Removing {member} from organization.")
            organization.remove_member(member)


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

    org = github_authenticate_with_org(
        config["github_organization"], access_token=config.get("github_access_token")
    )
    class_team = _get_team(org, "ucsb")
    team = _get_team(org, team_name)
    if team is None:
        team = org.create_team(team_name, permission="admin")
        # org.create_team doesn't support parent_team_id so edit it in manually
        team._patch(
            team._api,
            data=json.dumps({"parent_team_id": class_team.id, "privacy": "closed"}),
        )

    repo = _get_repository(org, team_name)
    if repo is None:  # Create repo and associate with the team
        repo = org.create_repository(
            team_name,
            has_wiki=False,
            team_id=team.id,
        )
        # repo.edit does not support `delete_branch_on_merge` so let's do it manually
        data = {
            "allow_rebase_merge": False,
            "allow_squash_merge": False,
            "delete_branch_on_merge": True,
        }
        response = repo._patch(repo._api, data=json.dumps(data))
    elif team not in list(repo.teams()):
        print(org.add_repo(repo, team))
    for user in user_names:  # Add users to the team
        team.add_or_update_membership(user)
    return 0


def download_repository(*, config, url):
    github = github_authenticate_with_org(
        config["github_organization"],
        access_token=config.get("github_access_token"),
        github_object=True,
    )
    parts = url.split("/")
    owner = parts[3]
    name = parts[4]

    repository = github.repository(owner, name)

    with io.BytesIO() as fp:
        repository.archive("zipball", fp, "")
        with zipfile.ZipFile(fp) as zfp:
            for member in zfp.infolist():
                suffix = member.filename.split("/", 1)[1]
                member.filename = f"{owner}/{suffix}"
                zfp.extract(member)


def github_authenticate_with_org(organization, access_token, github_object=False):
    """Authenticate to github and return the desired organization handle."""
    save_access_token = access_token is None

    github_organization = None
    while github_organization is None:
        if access_token is None:
            from getpass import getpass

            print(
                "Please set up a personal access token with 'public_repo' and 'admin:org' access.'"
            )
            print("https://github.com/settings/tokens")
            access_token = getpass(f"Personal Access Token: ")

        github = GitHub()
        github.login(token=access_token)
        try:  # Test login
            github_organization = github.membership_in(organization).organization
        except GitHubError as exc:
            if exc.code != 401:  # Bad Credentials
                raise
            print(f"{exc.message}. Try again.")
            access_token = None

    if save_access_token:
        update_config(github_access_token=access_token)

    if github_object:
        return github
    return github_organization
