import logging
import os
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


class TenableConfigError(RuntimeError):
    """Raised when Tenable configuration is incomplete."""


def _slugify(value: str) -> str:
    filtered = []
    for char in value.lower():
        if char.isalnum():
            filtered.append(char)
        elif char in ("-", "_"):
            filtered.append(char)
        else:
            filtered.append("-")
    slug = "".join(filtered).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "scan"


@dataclass
class TenableScanResult:
    scan_id: Optional[int]
    scan_uuid: Optional[str]


class TenableClient:
    def __init__(
        self,
        *,
        access_key: Optional[str],
        secret_key: Optional[str],
        base_url: str = "https://cloud.tenable.com",
        verify: bool = True,
        dry_run: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.verify = verify
        headers = {"Content-Type": "application/json"}

        if not dry_run:
            if not access_key or not secret_key:
                raise TenableConfigError(
                    "Tenable API keys are required unless running in dry-run mode"
                )
            headers["X-ApiKeys"] = f"accessKey={access_key}; secretKey={secret_key}"

        self.session.headers.update(headers)

    @classmethod
    def from_env(cls, *, dry_run: bool = False) -> "TenableClient":
        return cls(
            access_key=os.getenv("TENABLE_ACCESS_KEY"),
            secret_key=os.getenv("TENABLE_SECRET_KEY"),
            base_url=os.getenv("TENABLE_API_URL", "https://cloud.tenable.com"),
            verify=os.getenv("TENABLE_VERIFY_SSL", "true").lower() != "false",
            dry_run=dry_run,
        )

    def _request(self, method: str, endpoint: str, **kwargs):
        if self.dry_run:
            logger.debug("DRY-RUN would request %s %s %s", method, endpoint, kwargs)
            return None
        url = f"{self.base_url}{endpoint}"
        resp = self.session.request(method, url, timeout=60, **kwargs)
        resp.raise_for_status()
        if resp.content:
            try:
                return resp.json()
            except ValueError:
                return resp.content
        return None

    # Folder helpers
    def list_folders(self):
        data = self._request("GET", "/folders")
        if self.dry_run:
            return []
        return data.get("folders", [])

    def find_folder_id(self, name: str) -> Optional[int]:
        if self.dry_run:
            logger.info("DRY-RUN: assuming folder '%s' exists (id=0)", name)
            return 0
        for folder in self.list_folders():
            if folder.get("name") == name:
                return folder.get("id")
        return None

    def create_folder(self, name: str) -> Optional[int]:
        if self.dry_run:
            logger.info("DRY-RUN: would create folder '%s'", name)
            return 0
        data = self._request("POST", "/folders", json={"name": name})
        if isinstance(data, dict):
            return data.get("folder", {}).get("id")
        return None

    def ensure_folder(self, name: str) -> Optional[int]:
        folder_id = self.find_folder_id(name)
        if folder_id is not None:
            return folder_id
        return self.create_folder(name)

    # Template helpers
    def list_templates(self):
        data = self._request("GET", "/editor/scan/templates")
        if self.dry_run:
            return []
        templates = []
        if isinstance(data, dict):
            for tmpl in data.get("templates", []):
                templates.append(tmpl)
        return templates

    def resolve_template_uuid(self, template_name: str) -> Optional[str]:
        if self.dry_run:
            slug = _slugify(template_name)
            logger.info(
                "DRY-RUN: assuming template '%s' (uuid=dry-%s)", template_name, slug
            )
            return f"dry-{slug}"
        for template in self.list_templates():
            if template.get("name") == template_name:
                return template.get("uuid")
        raise TenableConfigError(
            f"Template '{template_name}' not found. "
            "Set TENABLE_TEMPLATE_UUID or update template name."
        )

    def prepare_template_uuid(
        self, template_name: str, template_uuid: Optional[str]
    ) -> str:
        if template_uuid:
            return template_uuid
        resolved = self.resolve_template_uuid(template_name)
        if not resolved:
            raise TenableConfigError(
                "Unable to resolve Tenable template UUID. "
                "Provide TENABLE_TEMPLATE_UUID environment variable."
            )
        return resolved

    # Scan operations
    def create_scan(
        self,
        *,
        name: str,
        targets: Iterable[str],
        template_uuid: str,
        folder_id: Optional[int],
        description: Optional[str] = None,
        scanner_id: Optional[str] = None,
        policy_id: Optional[str] = None,
    ) -> TenableScanResult:
        targets_str = ",".join(sorted({target.strip() for target in targets}))
        payload = {
            "uuid": template_uuid,
            "settings": {
                "name": name,
                "text_targets": targets_str,
            },
        }
        if folder_id is not None:
            payload["settings"]["folder_id"] = folder_id
        if description:
            payload["settings"]["description"] = description
        if scanner_id:
            payload["settings"]["scanner_id"] = scanner_id
        if policy_id:
            payload["settings"]["policy_id"] = policy_id

        if self.dry_run:
            logger.info(
                "DRY-RUN: would create scan name='%s' folder_id=%s targets=%s",
                name,
                folder_id,
                targets_str,
            )
            return TenableScanResult(scan_id=None, scan_uuid=None)

        data = self._request("POST", "/scans", json=payload)
        if not isinstance(data, dict):
            raise RuntimeError("Unexpected response while creating scan.")
        scan_info = data.get("scan", {})
        return TenableScanResult(
            scan_id=scan_info.get("id"),
            scan_uuid=scan_info.get("uuid"),
        )

    def launch_scan(self, scan_id: int) -> Optional[str]:
        if self.dry_run:
            logger.info("DRY-RUN: would launch scan id=%s", scan_id)
            return None
        data = self._request("POST", f"/scans/{scan_id}/launch")
        if isinstance(data, dict):
            return data.get("scan_uuid")
        return None

    def get_scan_status(self, scan_id: int) -> Optional[str]:
        if self.dry_run:
            logger.info("DRY-RUN: would poll scan id=%s", scan_id)
            return "dry-run"
        data = self._request("GET", f"/scans/{scan_id}")
        if isinstance(data, dict):
            return data.get("info", {}).get("status")
        return None

    def delete_scan(self, scan_id: int) -> None:
        if self.dry_run:
            logger.info("DRY-RUN: would delete scan id=%s", scan_id)
            return
        self._request("DELETE", f"/scans/{scan_id}")
