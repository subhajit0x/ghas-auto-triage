from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class GitHubAPIError(Exception):
    def __init__(self, status: int, message: str, body: str = "") -> None:
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status
        self.body = body


def _parse_next_url(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        m = re.search(r'<([^>]+)>;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


class GitHubClient:
    def __init__(self, token: str, api_version: str = "2022-11-28") -> None:
        self._token = token
        self._api_version = api_version
        self._base = "https://api.github.com"

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": self._api_version,
            "User-Agent": "0.6",
        }
        if extra:
            h.update(extra)
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        url = self._base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data: bytes | None = None
        headers = self._headers()
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                status = resp.getcode() or 200
                raw = resp.read().decode("utf-8", errors="replace")
                if status == 204 or not raw.strip():
                    return status, None
                return status, json.loads(raw)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise GitHubAPIError(e.code, e.reason, err_body) from e

    def get(self, path: str, params: dict[str, str] | None = None) -> Any:
        status, body = self._request("GET", path, params=params)
        if status >= 400:
            raise GitHubAPIError(status, "GET failed", str(body))
        return body

    def paginate_get(self, path: str, params: dict[str, str] | None = None) -> list[Any]:
        out: list[Any] = []
        url = self._base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        while url:
            req = urllib.request.Request(url, method="GET", headers=self._headers())
            ctx = ssl.create_default_context()
            try:
                with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                    chunk = json.loads(resp.read().decode("utf-8", errors="replace"))
                    if isinstance(chunk, list):
                        out.extend(chunk)
                    else:
                        out.append(chunk)
                    link = resp.headers.get("Link")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
                raise GitHubAPIError(e.code, e.reason, err_body) from e
            nxt = _parse_next_url(link)
            url = nxt or ""
        return out

    # --- Alert listing ---

    def list_dependabot_alerts(self, owner: str, repo: str, state: str = "open") -> list[Any]:
        return self.paginate_get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/dependabot/alerts",
            {"state": state, "per_page": "100"},
        )

    def list_code_scanning_alerts(self, owner: str, repo: str, state: str = "open") -> list[Any]:
        return self.paginate_get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/code-scanning/alerts",
            {"state": state, "per_page": "100"},
        )

    def list_secret_scanning_alerts(self, owner: str, repo: str, state: str = "open") -> list[Any]:
        return self.paginate_get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/secret-scanning/alerts",
            {"state": state, "per_page": "100"},
        )

    def get_dependabot_alert(self, owner: str, repo: str, alert_number: int) -> dict[str, Any]:
        r = self.get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/dependabot/alerts/{alert_number}",
        )
        return r if isinstance(r, dict) else {}

    def get_code_scanning_alert(self, owner: str, repo: str, alert_number: int) -> dict[str, Any]:
        r = self.get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/code-scanning/alerts/{alert_number}",
        )
        return r if isinstance(r, dict) else {}

    def get_secret_scanning_alert(self, owner: str, repo: str, alert_number: int) -> dict[str, Any]:
        r = self.get(
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/secret-scanning/alerts/{alert_number}",
        )
        return r if isinstance(r, dict) else {}

    # --- Repo metadata (visibility, topics, languages) ---

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        r = self.get(f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}")
        return r if isinstance(r, dict) else {}

    def list_org_repos(self, org: str, repo_type: str = "all", per_page: int = 100) -> list[Any]:
        return self.paginate_get(
            f"/orgs/{urllib.parse.quote(org)}/repos",
            {"type": repo_type, "per_page": str(per_page)},
        )

    # --- Alert comments ---

    def list_dependabot_alert_comments(self, owner: str, repo: str, alert_number: int) -> list[Any]:
        try:
            body = self.get(
                f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/dependabot/alerts/{alert_number}/comments",
            )
            return body if isinstance(body, list) else []
        except GitHubAPIError as e:
            if e.status == 404:
                return []
            raise

    def create_dependabot_alert_comment(self, owner: str, repo: str, alert_number: int, body: str) -> Any:
        status, result = self._request(
            "POST",
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/dependabot/alerts/{alert_number}/comments",
            json_body={"body": body},
        )
        if status not in (200, 201):
            raise GitHubAPIError(status, "create dependabot comment failed", str(result))
        return result

    def list_code_scanning_alert_comments(self, owner: str, repo: str, alert_number: int) -> list[Any]:
        try:
            body = self.get(
                f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/code-scanning/alerts/{alert_number}/comments",
            )
            return body if isinstance(body, list) else []
        except GitHubAPIError as e:
            if e.status == 404:
                return []
            raise

    def create_code_scanning_alert_comment(self, owner: str, repo: str, alert_number: int, body: str) -> Any:
        status, result = self._request(
            "POST",
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/code-scanning/alerts/{alert_number}/comments",
            json_body={"body": body},
        )
        if status not in (200, 201):
            raise GitHubAPIError(status, "create code scanning comment failed", str(result))
        return result

    def list_secret_scanning_alert_comments(self, owner: str, repo: str, alert_number: int) -> list[Any]:
        try:
            body = self.get(
                f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/secret-scanning/alerts/{alert_number}/comments",
            )
            return body if isinstance(body, list) else []
        except GitHubAPIError as e:
            if e.status in (404, 403):
                return []
            raise

    def create_secret_scanning_alert_comment(self, owner: str, repo: str, alert_number: int, body: str) -> Any:
        status, result = self._request(
            "POST",
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/secret-scanning/alerts/{alert_number}/comments",
            json_body={"body": body},
        )
        if status not in (200, 201):
            raise GitHubAPIError(status, "create secret scanning comment failed", str(result))
        return result

    # --- Auto-resolve: dismiss/resolve GHAS alerts ---

    def dismiss_dependabot_alert(
        self, owner: str, repo: str, alert_number: int, reason: str, comment: str,
    ) -> dict[str, Any]:
        status, result = self._request(
            "PATCH",
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/dependabot/alerts/{alert_number}",
            json_body={"state": "dismissed", "dismissed_reason": reason, "dismissed_comment": comment},
        )
        if status not in (200, 201):
            raise GitHubAPIError(status, "dismiss dependabot alert failed", str(result))
        return result if isinstance(result, dict) else {}

    def dismiss_code_scanning_alert(
        self, owner: str, repo: str, alert_number: int, reason: str, comment: str,
    ) -> dict[str, Any]:
        status, result = self._request(
            "PATCH",
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/code-scanning/alerts/{alert_number}",
            json_body={"state": "dismissed", "dismissed_reason": reason, "dismissed_comment": comment},
        )
        if status not in (200, 201):
            raise GitHubAPIError(status, "dismiss code scanning alert failed", str(result))
        return result if isinstance(result, dict) else {}

    def resolve_secret_scanning_alert(
        self, owner: str, repo: str, alert_number: int, resolution: str, comment: str,
    ) -> dict[str, Any]:
        status, result = self._request(
            "PATCH",
            f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/secret-scanning/alerts/{alert_number}",
            json_body={"state": "resolved", "resolution": resolution, "resolution_comment": comment},
        )
        if status not in (200, 201):
            raise GitHubAPIError(status, "resolve secret scanning alert failed", str(result))
        return result if isinstance(result, dict) else {}

    # --- List repos with GHAS ---

    def list_org_repos_with_security(self, org: str) -> list[dict[str, Any]]:
        repos = self.list_org_repos(org, repo_type="all")
        result: list[dict[str, Any]] = []
        for r in repos:
            if not isinstance(r, dict):
                continue
            sec = r.get("security_and_analysis") or {}
            has_ghas = any(
                isinstance(sec.get(k), dict) and sec[k].get("status") == "enabled"
                for k in ("advanced_security", "secret_scanning", "secret_scanning_push_protection",
                           "dependabot_security_updates")
            )
            if has_ghas or not r.get("private", True):
                result.append({
                    "full_name": r.get("full_name", ""),
                    "private": r.get("private", True),
                    "default_branch": r.get("default_branch", "main"),
                    "security_and_analysis": sec,
                })
        return result
