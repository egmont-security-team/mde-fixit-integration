"""
All functions and classes related to Microsoft Defender for Endpoint.
"""

from __future__ import annotations

from datetime import datetime
import logging
import re
import time
from typing import Literal, Optional

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
    """
    A Microsoft Defender for Endpoint client that can interact with the MDE API.
    """

    azure_mde_tenant: str
    azure_mde_client_id: str
    azure_mde_secret_value: str
    api_token: None | str

    def __init__(
        self,
        azure_mde_tenant: str,
        azure_mde_client_id: str,
        azure_mde_secret_value: str,
        authenticate=True,
    ):
        """
        Create a new Microsoft Defender for Endpoint client to interact with the MDE API.

        params:
            azure_mde_tenant:
                str: The Azure tenant ID for Microsoft Defender for Endpoint.
            azure_mde_client_id:
                str: The Azure client ID for Microsoft Defender for Endpoint.
            azure_mde_secret_value:
                str: The Azure secret value for Microsoft Defender for Endpoint.
            authenticate=True:
                bool: True if it should authenticate with Microsoft Defender for Endpoint.

        returns:
            MDEClient: The Microsoft Defender for Endpoint client.
        """
        self.azure_mde_tenant = azure_mde_tenant
        self.azure_mde_client_id = azure_mde_client_id
        self.azure_mde_secret_value = azure_mde_secret_value

        if authenticate:
            self.authenticate()

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_fixed(30),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def authenticate(self) -> None:
        """
        Authenticates with Azure and gets a new access token for Microsoft Defender for Endpoint.
        """
        res = requests.post(
            f"https://login.microsoftonline.com/{self.azure_mde_tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.azure_mde_client_id,
                "client_secret": self.azure_mde_secret_value,
                "scope": "https://api-eu.securitycenter.microsoft.com/.default",
            },
            timeout=120,
        )

        res.raise_for_status()

        self.api_token = res.json()["access_token"]

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
        odata_filter: Optional[str] = None,
    ) -> list[MDEDevice]:
        """
        Gets a list of all devices from Microsoft Defender for Endpoint.

        This might takes multiples requests, because Microsoft Defender for Endpoint
        only allows to fetch 10K devices at a time.

        params:
            filter=None:
                str: An OData filter to filter the devices.

        returns:
            list[MDEDevice]: The machines from Microsoft Defender for Endpoint.
        """
        devices: list[MDEDevice] = []

        odata_filter = f"?$filter={odata_filter}" or ""
        devices_url = f"https://api.securitycenter.microsoft.com/api/machines{odata_filter}"

        while devices_url:
            res = requests.get(
                devices_url,
                headers={"Authorization": f"Bearer {self.api_token}"},
                timeout=300,
            )

            res.raise_for_status()

            json = res.json()

            # Get the new devices from the request.
            new_devices = json["value"]
            logger.debug(f"Fetched {len(new_devices)} new devices from Microsoft Defender for Endpoint.")

            # Turn the JSON payloads from MDE into MDEDevice objects.
            for payload in new_devices:
                new_device_id = payload["id"]

                try:
                    devices.append(
                        MDEDevice(
                            uuid=new_device_id,
                            name=payload["computerDnsName"],
                            health=payload["healthStatus"],
                            operating_system=payload["osPlatform"],
                            onboarding_status=payload["onboardingStatus"],
                            tags=payload["machineTags"],
                            first_seen=datetime.fromisoformat(
                                payload["firstSeen"]),
                        )
                    )
                except ValueError:
                    custom_dimensions = {
                        "payload": json.stringify(payload),
                        "device_id": new_device_id,
                    }
                    logger.error(
                        f'Couldn\'t create a new "MDEDevice" from the payload for device with UUID={new_device_id}.',
                        extra=custom_dimensions,
                    )

            # The Microsoft Defender API has a limit of 10k devices per request.
            # In case this URL exists, this means that more devices can be fetched.
            # This URL given here can be used to fetch the next devices.
            devices_url = json.get("@odata.nextLink")

        logger.info(
            f"Fetched a total of {len(devices)} devices from Microsoft Defender for Endpoint."
        )

        return devices

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
    ) -> Optional[bool]:
        """
        Alters a tag for a given device using Microsoft Defender for Endpoint.

        params:
            device:
                MDEDevice: The device to alter the tag from.
            tag:
                str: The tag to alter.
            action:
                Literal["Add", "Remove"]: The actions to perform.
            sleep=None:
                Optional[float]: Will sleep for 'sleep' seconds after the request.

        returns:
            bool: True if it successfully removes the tag otherwise False.
            None: If the request fails.
        """
        res = requests.post(
            f"https://api.securitycenter.microsoft.com/api/machines/{device.uuid}/tags",
            headers={"Authorization": f"Bearer {self.api_token}"},
            json={
                "Value": tag,
                "Action": action,
            },
            timeout=300,
        )

        if delay_str := res.headers.get("Retry-After"):
            # Add 4 seconds to the delay to make sure we
            # don't hit the limit immediately after.
            delay = int(delay_str) + 4
            logger.info(f"The request was rate limited. Retrying in {delay} seconds.")
            time.sleep(delay)
            self.alter_device_tag(device, tag, action)

        res.raise_for_status()

        logger.info(f'Performed action "{action}" with tag "{tag}" on device {device}.')

        return True

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

        returns:
            list[MDEVulnerability]: The vulnerabilities of the machine.
        """
        vulnerabilities: list[MDEVulnerability] = []

        # IMPORTANT: The "DeviceInfo" table is broken and we can't rely on it.
        # If needed to filter in devices, use get_devices as a mapping instead
        # to access devices fields.
        kudos_query: str = """
        DeviceTvmSoftwareVulnerabilities
        | where VulnerabilitySeverityLevel == 'Critical'
        | join kind=inner (
            DeviceTvmSoftwareVulnerabilitiesKB
            | where PublishedDate <= datetime_add('day', -25, now())
            | project CveId, VulnerabilityDescription, CvssScore
        ) on CveId
        | join kind=inner (
            DeviceInfo
            | summarize arg_max(Timestamp, *) by DeviceId
            | project DeviceId
        ) on DeviceId
        | summarize Devices = make_set(DeviceId) by CveId, SoftwareName, SoftwareVendor, VulnerabilityDescription, CvssScore
        """

        cve_url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

        while cve_url:
            res = requests.post(
                cve_url,
                headers={"Authorization": f"Bearer {self.api_token}"},
                json={"Query": kudos_query},
                timeout=300,
            )

            res.raise_for_status()

            json = res.json()

            new_vulnerabilities = json["Results"]
            logger.info(
                f"Fetched {len(new_vulnerabilities)} new vulnerabilities from Microsoft Defender for Endpoint."
            )

            for payload in new_vulnerabilities:
                try:
                    vulnerabilities.append(
                        MDEVulnerability(
                            cve_id=payload["CveId"],
                            cve_score=payload["CvssScore"],
                            devices=payload["Devices"],
                            description=payload["VulnerabilityDescription"],
                            software_name=payload["SoftwareName"],
                            software_vendor=payload["SoftwareVendor"],
                        )
                    )
                except KeyError:
                    logger.error(f'Couldn\'t create a new "MDEVulnerability" from the payload {payload}.')

            # The Microsoft Defender API has a limit of 8k rows per request.
            # In case this URL exists, this means that more rows can be fetched.
            # The URL given here can be used to fetch the next devices.
            cve_url = json.get("@odata.nextLink")

        logger.info(f"Fetched a total of {len(vulnerabilities)} devices from Microsoft Defender for Endpoint.")

        return vulnerabilities

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

        returns:
            list[str]: The device users.
        """
        users: list[str] = []

        users_url = f"https://api.securitycenter.microsoft.com/api/machines/{device.uuid}/logonusers"

        while users_url:
            res = requests.get(
                users_url,
                headers={"Authorization": f"Bearer {self.api_token}"},
                timeout=300,
            )

            res.raise_for_status()

            json = res.json()

            new_users = json["value"]
            logger.debug(
                f"Fetched {len(new_users)} new users from Microsoft Defender for Endpoint."
            )

            users.extend(user["accountName"] for user in new_users)

            users_url = json.get("@odata.nextLink")

        logger.info(
            f"Fetched a total of {len(users)} users from Microsoft Defender for Endpoint."
        )

        return users

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        reraise=True,
    )
    def get_device_recommendations(
        self,
        device: MDEDevice,
        odata_filter:Optional[str]=None,
    ) -> list[str]:
        """
        Returns a list of recommendations for a given device.

        The default filter is set to only get recommendations that are of type "Update".
        This is because we are only interested in recommendations that are related to
        updating software.

        params:
            device:
                MDEDevice: The device to get recommendations for.
            odata_filter="remediationType eq 'Update'":
                str: The OData filter to filter the recommendations.

        returns:
            list[str]: The recommendations for the device.
        """
        recommendations = []

        odata_filter = f"?$filter={odata_filter}" or ""
        recommendation_url: str = f"https://api-eu.securitycenter.microsoft.com/api/machines/{device.uuid}/recommendations{odata_filter}"

        while recommendation_url:
            res = requests.get(
                recommendation_url,
                headers={"Authorization": f"Bearer {self.api_token}"},
                timeout=300,
            )

            res.raise_for_status()

            json = res.json()

            for recommendation in json["value"]:
                recommendations.append(recommendation["recommendationName"])

            recommendation_url = json.get("@odata.nextLink")

        logger.info(f"Fetched a total of {len(recommendations)} recommendation for device {device} from Microsoft Defender for Endpoint.")

        return recommendations


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

    def __init__(
        self,
        uuid: str,
        name: str,
        health: str,
        operating_system: str,
        onboarding_status: str,
        tags: list[str],
        first_seen: datetime,
    ):
        """
        Create a new Microsoft Defender for Endpoint device.

        params:
            uuid:
                str: The UUID of the Microsoft Defender for Endpoint device.
            name:
                str: The name of the Microsoft Defender for Endpoint device.
            health:
                str: The health of the Microsoft Defender for Endpoint device.
            operating_system:
                str: The OS of the Microsoft Defender for Endpoint device.
            onboarding_status:
                str: The onboarding status of the Microsoft Defender for Endpoint device.
            tags:
                list[str]: The tags of the Microsoft Defender for Endpoint device.
            first_seen:
                datetime: The first time the device was seen in Microsoft Defender for Endpoint.

        returns:
            MDEDevice: The Microsoft Defender for Endpoint device.
        """
        self.uuid = uuid
        self.name = name
        self.health = health
        self.os = operating_system
        self.onboarding_status = onboarding_status
        self.tags = tags
        self.first_seen = first_seen

    def __str__(self) -> str:
        """
        The device represented as a string.
        """
        if self.name:
            return f'"{self.name}" (UUID="{self.uuid}")'
        return f'"UUID={self.uuid}"'

    def __eq__(self, other: MDEDevice) -> bool:
        """
        Two devices are equal if they have the same UUID.
        """
        return self.uuid == other.uuid

    def __ne__(self, other: MDEDevice) -> bool:
        """
        Two devices are not equal if they have different UUIDs.
        """
        return not self.__eq__(other)

    def is_server(self) -> bool:
        """
        Returns if the device is a server or not.

        returns:
            bool: True if the device is a server.
        """
        return any(os in self.os.lower() for os in [
            "server",
            "redhatenterpriselinux",
            "ubuntu"
        ])

    def should_skip(
        self, automation: Literal["DDC2", "DDC3", "CVE"], cve: None | str = None
    ) -> bool:
        """
        Returns if the device should be skipped for a given automation.

        Automation names:
            DDC2: The Data Defender task 2 (Cleanup FixIt tags).
            DDC3: The Data Defender task 3 (Cleanup ZZZ tags).
            CVE: The CVE automation that create tickets for vulnerable devices.

        params:
            automation_names:
                str: The name of the automation to skip. The names can be found above.

        returns:
            bool: True if the device should be skipped.
        """
        match automation:
            case "DDC2":
                pattern = re.compile(r"^SKIP-DDC2$")
            case "DDC3":
                pattern = re.compile(r"^SKIP-DDC3$")
            case "CVE":
                pattern = re.compile(
                    r"^SKIP-CVE(?:-\[(?P<CVE>CVE-\d{4}-\d{4,7})\])?$")
            case _:
                logger.warning(f'''The automation "{automation}" is not recognized. Can\'t peform a valid "should_skip()" check, so we skip the device.''')
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

    def __init__(
        self,
        cve_id: str,
        cve_score: int,
        devices: list[str],
        description: str,
        software_name: str,
        software_vendor: str,
    ):
        """
        Create a new Microsoft Defender for Endpoint vulnerability.

        params:
            cve_id:
                str: The UUID of the Microsoft Defender for Endpoint vulnerability.
            csv_score:
                int: The score of the vulnerability.
            description:
                str: The vulnerability description.
            devices:
                list[str]: A list of device UUIDs hit by the vulnerability.
            softwareName:
                str: The name of the software vulnerable.
            softwareVendor:
                str: The vendor of the software vulnerable.

        returns:
            MDEVulnerability: The Microsoft Defender Vulnerability.
        """
        self.cve_id = cve_id
        self.cve_score = cve_score
        self.description = description
        self.devices = devices
        self.software_name = software_name
        self.software_vendor = software_vendor

    def is_sever_software(self) -> bool:
        """
        Returns if the software is a server software or not.

        returns:
            bool: True if the software is a server software.
        """
        return "server" in self.software_name.lower()

    def __str__(self):
        """
        The vulnerability represented as a string.
        """
        if self.devices and len(self.devices) > 5:
            return f'"{self.cve_id}" (TotalDevices: {len(self.devices)})'
        return f'"{self.cve_id}"'

    def __eq__(self, other: MDEVulnerability):
        """
        Two vulnerabilities are equal if they have the same UUID.
        """
        return self.cve_id == other.cve_id

    def __ne__(self, other: MDEVulnerability):
        """
        Two vulnerabilities are not equal if they have different UUIDs.
        """
        return not self.__eq__(other)
