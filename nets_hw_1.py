import asyncio
import time

import aiohttp
import plotly.graph_objects as go
from collections import defaultdict

import config

TOKEN = config.MY_TOKEN
HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": f"token {TOKEN}",
    "User-Agent": "NetsHW"
}


async def get_repositories(session: aiohttp.ClientSession, page: int, org_name: str = "Netflix") -> list | None:
    """Returns repositories from organization's GitHub."""
    url = f"https://api.github.com/orgs/{org_name}/repos?page={page}&per_page=100"
    async with session.get(url, headers=HEADERS) as response:
        if response.status == 200:
            return await response.json()

    return None


async def get_commits(session: aiohttp.ClientSession, commits_url: str) -> list:
    """Returns commits for a repository."""
    async with session.get(commits_url, headers=HEADERS) as response:
        if response.status == 200:
            return await response.json()

    return []


async def process_repository(session: aiohttp.ClientSession, repository: dict) -> dict:
    """Process a single repository and return stats."""
    local_stats = defaultdict(int)
    commits_url = repository["commits_url"][:repository["commits_url"].rfind("{")]
    commits = await get_commits(session, commits_url)
    for commit in commits:
        if isinstance(commit, dict):
            message: str = commit["commit"]["message"]
            if "merge pull request #" not in message.lower():
                email = commit["commit"]["author"]["email"]
                local_stats[email] += 1

    return local_stats


async def process_all_repositories(repositories: list) -> dict:
    """Process all repositories concurrently."""
    print(repositories[0])
    async with aiohttp.ClientSession() as session:
        tasks = [process_repository(session, repository) for repository in repositories]
        results = await asyncio.gather(*tasks)

    global_stats = defaultdict(int)
    for local_stats in results:
        for email, count in local_stats.items():
            global_stats[email] += count

    return global_stats


def stats_output(stats: dict, org_name: str = "Netflix") -> None:
    """Uses plotly.graph_objects for graphical html output."""
    sorted_stats = sorted(stats.items(), key=lambda item: item[1], reverse=True)[:100]
    x, y = [stat[0] for stat in sorted_stats], [stat[1] for stat in sorted_stats]
    print(sum(y))
    fig = go.Figure(data=[go.Bar(x=x, y=y)])
    fig.update_layout(
        title=f'Commit Statistics for Top 100 Commiters of {org_name}',
        xaxis_title='Users',
        yaxis_title='Commits',
        width=1440,
        height=810
    )
    fig.update_traces(hovertemplate='User: %{x}<br>Commits: %{y}')
    fig.write_html("interactive_commit_stats.html")
    fig.show()


async def main():
    start = time.time()
    org_name = "Netflix"
    page = 1
    all_repositories = []

    async with aiohttp.ClientSession() as session:
        while True:
            repositories = await get_repositories(session, page, org_name)
            if repositories is None or len(repositories) < 100:
                if repositories:
                    all_repositories.extend(repositories)
                break
            all_repositories.extend(repositories)
            page += 1

    stats = await process_all_repositories(all_repositories)
    stats_output(stats, org_name)
    finish = time.time()
    print(f"Finished in {finish - start} seconds")


if __name__ == "__main__":
    asyncio.run(main())