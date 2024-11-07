"""All functions and classes related to Microsoft Defender for Endpoint."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from json import dumps
from typing import Any, Callable, Literal, Optional

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_fixed,
)

logger = logging.getLogger(__name__)


class MDEClient:
    """A client that can interact with the MDE API."""

    azure_mde_tenant: str
    azure_mde_client_id: str
    azure_mde_secret_value: str
    api_token: str | None

    def __init__(
        self,
        azure_mde_tenant: str,
        azure_mde_client_id: str,
        azure_mde_secret_value: str,
        authenticate: bool = True,
    ):
        """
        Create a new client to interact with the MDE API.

        Parameters
        ----------
        azure_mde_tenant : str
            Azure tenant ID for Microsoft Defender for Endpoint.
        azure_mde_client_id : str
            Azure client ID for Microsoft Defender for Endpoint.
        azure_mde_secret_value : str
            Azure secret value for Microsoft Defender for Endpoint.
        authenticate : bool
            If client should authenticate straight away.

        """
        self.azure_mde_tenant = azure_mde_tenant
        self.azure_mde_client_id = azure_mde_client_id
        self.azure_mde_secret_value = azure_mde_secret_value
        self.api_token = None
        
        if authenticate:
            self.api_token = self.authenticate()

    def _make_request(
        self,
        url: str,
        method: Callable[..., requests.Response],
        authorized_endpoint: bool = True,
        **kwargs,
    ) -> requests.Response:

        headers = {} 

        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        if extra_headers := kwargs.pop("headers", None):
            headers.update(extra_headers)

        res = method(url, headers=headers, **kwargs)

        if delay := res.headers.get("Retry-After"):
            time.sleep(int(delay))

            return self._make_request(
                url,
                method,
                authorized_endpoint,
                **kwargs,
            )

        res.raise_for_status()

        return res

    def _make_paginated_request(
        self,
        url: str,
        method: Callable[..., requests.Response],
        value_key: str = "value",
        next_link_key: str = "@odata.nextLink",
        _data: list[Any] | None = None,
        **kwargs,
    ) -> list[Any]:
        if _data is None:
            _data = []

        res = self._make_request(url, method, **kwargs)
        json = res.json()

        value = json.get(value_key)

        if value is None:
            raise ValueError("wrong value key given")

        _data.extend(value)

        if next_url := json.get(next_link_key):
            return self._make_paginated_request(
                next_url,
                method,
                value_key,
                next_link_key,
                _data,
                **kwargs,
            )

        return _data

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_fixed(30),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def authenticate(self) -> None:
        """Authenticate client with MDE."""
        res = self._make_request(
            f"https://login.microsoftonline.com/{self.azure_mde_tenant}/oauth2/v2.0/token",
            requests.post,
            authorized_endpoint=False,
            data={
                "grant_type": "client_credentials",
                "client_id": self.azure_mde_client_id,
                "client_secret": self.azure_mde_secret_value,
                "scope": "https://api-eu.securitycenter.microsoft.com/.default",
            },
            timeout=120,
        )

        json = res.json()

        return json["access_token"]

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def alter_device_tag(
        self,
        device: MDEDevice,
        tag: str,
        action: Literal["Add", "Remove"],
    ) -> bool | None:
        """
        Alters a tag for a given device.

        Parameters
        ----------
        device : MDEDevice
            Device to alter the tag from.
        tag : str
            Tag to alter.
        action : Literal["Add", "Remove"]:
            Action to perform.

        Returns
        -------
        bool
            True if it successfully removes the tag.

        """
        self._make_request(
            f"https://api.securitycenter.microsoft.com/api/machines/{device.uuid}/tags",
            requests.post,
            timeout=300,
            json={
                "Value": tag,
                "Action": action,
            },
        )

        logger.debug(f'performed "{action}" with tag "{tag}" on device {device}')

        return True

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_fixed(120),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def get_devices(
        self,
        odata_filter: str | None = None,
    ) -> list[MDEDevice]:
        """
        Get a list of all devices from MDE.

        This might takes multiples requests, because MDE
        only allows to fetch 10K devices at a time.

        Parameters
        ----------
        odata_filter : Optional[str]
            OData filter to filter the devices.

        Returns
        -------
            list[MDEDevice]: The machines from MDE.

        """
        odata_filter = f"?$filter={odata_filter}" or ""
        devices_url = f"https://api.securitycenter.microsoft.com/api/machines{odata_filter}"

        devices_data = self._make_paginated_request(
            devices_url,
            requests.get,
        )

        return [MDEDevice.from_payload(d) for d in devices_data]

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_fixed(120),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def get_vulnerabilities(self) -> list[MDEVulnerability]:
        """
        Get the vulnerabilities of the machine.

        Returns
        -------
            list[MDEVulnerability]: The vulnerabilities of the machine.

        """
        # IMPORTANT: The "DeviceInfo" table is broken and we can't rely on it.
        # If needed to filter in devices, use get_devices as a mapping instead
        # to access devices fields.
        kudos_query: str = """
        DeviceTvmSoftwareVulnerabilities
        | where VulnerabilitySeverityLevel == 'Critical'
        | join kind=inner (
            DeviceTvmSoftwareVulnerabilitiesKB
            | where PublishedDate <= datetime_add('day', -40, now())
            | project CveId, VulnerabilityDescription, CvssScore
        ) on CveId
        | join kind=inner (
            DeviceInfo
            | summarize arg_max(Timestamp, *) by DeviceId
            | project DeviceId
        ) on DeviceId
        | summarize Devices = make_set(DeviceId) by CveId, SoftwareName, SoftwareVendor, VulnerabilityDescription, CvssScore
        """  # noqa: E501

        cve_url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

        vulnerabilities_data = self._make_paginated_request(
            cve_url,
            requests.post,
            json={"Query": kudos_query},
            value_key="Results",
            timeout=300,
        )

        return [MDEVulnerability.from_payload(v) for v in vulnerabilities_data]

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def get_device_users(self, device: MDEDevice) -> list[str]:
        """
        Get a list of users on the device.

        Returns
        -------
        list[str]
            The device users.

        """
        users_url = f"https://api.securitycenter.microsoft.com/api/machines/{device.uuid}/logonusers"

        users_data = self._make_paginated_request(
            users_url,
            requests.get,
            timeout=300,
        )

        return [user["accountName"] for user in users_data]

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        reraise=True,
    )
    def get_device_recommendations(
        self,
        device: MDEDevice,
        odata_filter: str | None = None,
    ) -> list[str]:
        """
        List of recommendations for a given device.

        Parameters
        ----------
        device : MDEDevice
            Device to get recommendations for.
        odata_filter : str
            OData filter to filter the recommendations.

        Returns
        -------
        list[str]
            The recommendations for the device.

        """
        odata_filter = f"?$filter={odata_filter}" or ""
        recommendation_url: str = f"https://api-eu.securitycenter.microsoft.com/api/machines/{device.uuid}/recommendations{odata_filter}"

        recommendations_data = self._make_paginated_request(
            recommendation_url,
            requests.get,
            timeout=300,
        )

        return [r["recommendationName"] for r in recommendations_data]


@dataclass
class MDEDevice:
    """
    A class that represents a Microsoft Defender for Endpoint client.

    See below for the class schema properties:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/machine?view=o365-worldwide#properties
    """

    uuid: str
    name: str
    health: str
    os: str
    onboarding_status: str
    tags: list[str]
    first_seen: datetime

    def __str__(self) -> str:
        """
        Device represented as a string.

        Returns
        -------
        str
            The device as a string

        """
        if self.name:
            return f'"{self.name}" (UUID="{self.uuid}")'
        return f'"UUID={self.uuid}"'

    def __eq__(self, other: MDEDevice) -> bool:
        """
        Two devices are equal if they have the same UUID.

        Returns
        -------
        bool
            True if two devices are equal.

        """
        return self.uuid == other.uuid

    def __ne__(self, other: MDEDevice) -> bool:
        """
        Two devices are not equal if they have different UUIDs.

        Returns
        -------
        bool
            True if two devices are not equal.

        """
        return not self.__eq__(other)

    def __hash__(self):
        """
        Get a hash of the device.

        Returns
        -------
        int
            The hash of the device

        """
        return hash(self.uuid)

    def is_server(self) -> bool:
        """
        If the device is a server or not.

        Returns
        -------
        bool
            True if the device is a server.

        """
        server_os = ["server", "redhatenterpriselinux", "ubuntu"]
        return any(os in self.os.lower() for os in server_os)

    def should_skip(
        self,
        automation: Literal["DDC2", "DDC3", "CVE"],
        cve: None | str = None,
    ) -> bool:
        """
        If the device should be skipped for a given automation.

        Automations
        -----------
        DDC2: The Data Defender task 2 (Cleanup ticket tags).

        DDC3: The Data Defender task 3 (Cleanup ZZZ tags).

        CVE: The CVE automation that create tickets for vulnerable devices.

        Parameters
        ----------
        automation : str
            Name of the automation to skip. The names can be found above.
        cve : None | str
            CVE to include in skip check.

        Returns
        -------
        bool
            True if the device should be skipped.

        """
        match automation:
            case "DDC2":
                pattern = re.compile(r"^SKIP-DDC2$")
            case "DDC3":
                pattern = re.compile(r"^SKIP-DDC3$")
            case "CVE":
                pattern = re.compile(r"^SKIP-CVE(?:-\[(?P<CVE>CVE-\d{4}-\d{4,7})\])?$")
            case _:
                logger.warning(
                    f"""automation "{automation}" is not recognized;
                    can\'t peform a valid "should_skip()" check;
                    device is skipped""",
                )
                return True

        for tag in self.tags:
            if match := re.fullmatch(pattern, tag):
                # Special logic for CVE automation
                if automation == "CVE":
                    groups = match.groupdict()
                    cve_from_tag = groups.get("CVE")
                    if cve_from_tag and cve_from_tag != cve:
                        continue

                return True

        return False
    
    @staticmethod
    def from_payload(payload: dict[str, Any]) -> MDEDevice:
        """
        Get a device from a request payload.

        Parameters
        ----------
        payload : dict[str, Any]
            The request payload.

        Returns
        -------
        MDEDevice
            Returns the device from the payload.

        """
        return MDEDevice(
            uuid=payload["id"],
            name=payload["computerDnsName"],
            health=payload["healthStatus"],
            os=payload["osPlatform"],
            onboarding_status=payload["onboardingStatus"],
            tags=payload["machineTags"],
            first_seen=datetime.fromisoformat(payload["firstSeen"]),
        )


@dataclass
class MDEVulnerability:
    """
    A class that represents a Microsoft Defender for Endpoint vulnerability.

    See below for the class schema properties:
    https://learn.microsoft.com/en-us/defender-endpoint/api/vulnerability?view=o365-worldwide#properties
    """

    cve_id: str
    cve_score: int
    devices: list[str]
    description: str
    software_name: str
    software_vendor: str

    def is_server_software(self) -> bool:
        """
        If the software is a server software or not.

        Returns
        -------
        bool
            True if the software is a server software.

        """
        return "server" in self.software_name.lower()

    def __str__(self):
        """
        Vulnerability represented as a string.

        Returns
        -------
        str
            A vulnerability represented as a string.

        """
        if self.devices and len(self.devices) > 1:
            return f'"{self.cve_id}" (TotalDevices: {len(self.devices)})'
        return f'"{self.cve_id}"'

    def __eq__(self, other: MDEVulnerability):
        """
        Two vulnerabilities are equal if they have the same CVE ID.

        Returns
        -------
        bool
            True if two vulnerabilities are equal.

        """
        return self.cve_id == other.cve_id

    def __ne__(self, other: MDEVulnerability):
        """
        Two vulnerabilities are not equal if they have a different CVE ID.

        Returns
        -------
        bool
            True if two vulnerabilities are not equal.

        """
        return not self.__eq__(other)

    def __hash__(self):
        """
        Get a hash of the vulnerability.

        Returns
        -------
        int
            The hash of the vulnerability

        """
        return hash(self.cve_id)

    @staticmethod
    def from_payload(payload: dict[str, Any]) -> MDEVulnerability:
        """
        Get a vulnerability from a request payload.

        Parameters
        ----------
        payload : dict[str, Any]
            The request payload.

        Returns
        -------
        MDEVulnerability
            Returns the vulnerability from the payload.

        """
        return MDEVulnerability(
            cve_id=payload["CveId"],
            cve_score=payload["CvssScore"],
            devices=payload["Devices"],
            description=payload["VulnerabilityDescription"],
            software_name=payload["SoftwareName"],
            software_vendor=payload["SoftwareVendor"],
        )
