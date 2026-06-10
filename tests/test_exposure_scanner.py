from __future__ import annotations

from unittest.mock import MagicMock

from ghas_llm.exposure_scanner import scan_org_exposure


def test_scan_org_exposure_finds_public_repos() -> None:
    client = MagicMock()
    client.list_org_repos.return_value = [
        {"name": "public-app", "visibility": "public", "private": False,
         "default_branch": "main", "pushed_at": "2024-01-01", "topics": ["web"]},
        {"name": "private-svc", "visibility": "private", "private": True,
         "default_branch": "main", "pushed_at": "2024-01-01", "topics": []},
    ]
    client.list_secret_scanning_alerts.return_value = [
        {"secret_type_display_name": "AWS Access Key", "secret_type": "aws_access_key_id",
         "state": "open", "created_at": "2024-01-01", "push_protection_bypassed": False},
    ]

    result = scan_org_exposure(client, "test-org")
    assert result["public_repo_count"] == 1
    assert result["public_repos"][0]["name"] == "test-org/public-app"
    assert result["exposed_secret_count"] == 1
    assert result["exposed_secrets"][0]["secret_type"] == "AWS Access Key"


def test_scan_org_exposure_no_public_repos() -> None:
    client = MagicMock()
    client.list_org_repos.return_value = [
        {"name": "internal", "visibility": "private", "private": True},
    ]
    result = scan_org_exposure(client, "secure-org")
    assert result["public_repo_count"] == 0
    assert result["exposed_secret_count"] == 0


def test_scan_org_exposure_handles_api_error() -> None:
    client = MagicMock()
    from ghas_llm.github_api import GitHubAPIError
    client.list_org_repos.side_effect = GitHubAPIError(403, "forbidden")
    result = scan_org_exposure(client, "no-access-org")
    assert "error" in result
