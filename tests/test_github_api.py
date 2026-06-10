from __future__ import annotations

from unittest.mock import MagicMock, patch

from ghas_llm.github_api import GitHubClient


@patch.object(GitHubClient, "_request")
def test_dismiss_dependabot_alert(mock_req: MagicMock) -> None:
    mock_req.return_value = (200, {"state": "dismissed"})
    client = GitHubClient("tok")
    result = client.dismiss_dependabot_alert("o", "r", 5, "inaccurate", "auto")
    assert result["state"] == "dismissed"
    mock_req.assert_called_once()
    args = mock_req.call_args
    assert args[0][0] == "PATCH"
    assert "/dependabot/alerts/5" in args[0][1]
    assert args[1]["json_body"]["state"] == "dismissed"


@patch.object(GitHubClient, "_request")
def test_dismiss_code_scanning_alert(mock_req: MagicMock) -> None:
    mock_req.return_value = (200, {"state": "dismissed"})
    client = GitHubClient("tok")
    result = client.dismiss_code_scanning_alert("o", "r", 3, "won't fix", "auto")
    assert result["state"] == "dismissed"
    assert "/code-scanning/alerts/3" in mock_req.call_args[0][1]


@patch.object(GitHubClient, "_request")
def test_resolve_secret_scanning_alert(mock_req: MagicMock) -> None:
    mock_req.return_value = (200, {"state": "resolved"})
    client = GitHubClient("tok")
    result = client.resolve_secret_scanning_alert("o", "r", 9, "false_positive", "auto")
    assert result["state"] == "resolved"
    body = mock_req.call_args[1]["json_body"]
    assert body["state"] == "resolved"
    assert body["resolution"] == "false_positive"


@patch.object(GitHubClient, "get")
def test_get_dependabot_alert(mock_get: MagicMock) -> None:
    mock_get.return_value = {"number": 1, "state": "open"}
    client = GitHubClient("tok")
    r = client.get_dependabot_alert("o", "r", 1)
    assert r["number"] == 1
    assert "/dependabot/alerts/1" in mock_get.call_args[0][0]


@patch.object(GitHubClient, "get")
def test_get_code_scanning_alert(mock_get: MagicMock) -> None:
    mock_get.return_value = {"number": 2}
    client = GitHubClient("tok")
    r = client.get_code_scanning_alert("o", "r", 2)
    assert r["number"] == 2
    assert "/code-scanning/alerts/2" in mock_get.call_args[0][0]


@patch.object(GitHubClient, "get")
def test_get_secret_scanning_alert(mock_get: MagicMock) -> None:
    mock_get.return_value = {"number": 3}
    client = GitHubClient("tok")
    r = client.get_secret_scanning_alert("o", "r", 3)
    assert r["number"] == 3


@patch.object(GitHubClient, "list_org_repos")
def test_list_org_repos_with_security(mock_list: MagicMock) -> None:
    mock_list.return_value = [
        {
            "full_name": "org/repo1",
            "private": False,
            "default_branch": "main",
            "security_and_analysis": {
                "advanced_security": {"status": "enabled"},
            },
        },
        {
            "full_name": "org/repo2",
            "private": True,
            "default_branch": "main",
            "security_and_analysis": {},
        },
        {
            "full_name": "org/repo3",
            "private": True,
            "default_branch": "develop",
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
            },
        },
    ]
    client = GitHubClient("tok")
    result = client.list_org_repos_with_security("org")
    names = [r["full_name"] for r in result]
    assert "org/repo1" in names
    assert "org/repo3" in names
    assert "org/repo2" not in names
