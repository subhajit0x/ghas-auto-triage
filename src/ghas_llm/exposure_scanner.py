from __future__ import annotations

from typing import Any

from ghas_llm.github_api import GitHubAPIError, GitHubClient


def scan_org_exposure(client: GitHubClient, org: str) -> dict[str, Any]:
    results: dict[str, Any] = {"org": org, "public_repos": [], "exposed_secrets": []}
    try:
        repos = client.list_org_repos(org, repo_type="public")
    except GitHubAPIError as e:
        results["error"] = str(e)
        return results

    for repo in repos:
        if not isinstance(repo, dict):
            continue
        name = repo.get("name", "")
        vis = repo.get("visibility", "")
        private = repo.get("private", True)
        if vis == "public" or not private:
            entry: dict[str, Any] = {
                "name": f"{org}/{name}",
                "visibility": vis or "public",
                "default_branch": repo.get("default_branch", ""),
                "pushed_at": str(repo.get("pushed_at", "")),
                "topics": repo.get("topics", []),
            }
            results["public_repos"].append(entry)

            try:
                secrets = client.list_secret_scanning_alerts(org, name, state="open")
                if secrets:
                    for s in secrets[:10]:
                        if isinstance(s, dict):
                            results["exposed_secrets"].append({
                                "repo": f"{org}/{name}",
                                "secret_type": s.get("secret_type_display_name") or s.get("secret_type"),
                                "state": s.get("state"),
                                "created_at": str(s.get("created_at", "")),
                                "push_protection_bypassed": s.get("push_protection_bypassed"),
                            })
            except GitHubAPIError:
                pass

    results["public_repo_count"] = len(results["public_repos"])
    results["exposed_secret_count"] = len(results["exposed_secrets"])
    return results
