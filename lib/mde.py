"""
All functions and classes related to Microsoft Defender for Endpoint.
"""

import time
import re
import requests

from lib.logging import logger


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
    ) -> "MDEClient":
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

    def authenticate(self) -> None:
        """
        Authenticates with Azure and gets a new API key for Microsoft Defender for Endpoint.
        """

        res = requests.post(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(
                self.azure_mde_tenant
            ),
            data={
                "grant_type": "client_credentials",
                "client_id": self.azure_mde_client_id,
                "client_secret": self.azure_mde_secret_value,
                "scope": "https://api-eu.securitycenter.microsoft.com/.default",
            },
        )

        if not res.ok:
            status_code = res.status_code
            custom_dimensions = {"status": status_code, "body": res.content}
            logger.error(
                "Couldn't get Microsoft Defender token from Microsoft authentication flow.",
                extra={"custom_dimensions": custom_dimensions},
            )
            return ""

        token = res.json().get("access_token")

        if not token:
            custom_dimensions = {"status": status_code, "body": res.content}
            logger.error(
                "The Microsoft Defender token was not provided in the request even tho it is was successful.",
                extra={"custom_dimensions": custom_dimensions},
            )

        self.api_token = token

    def get_devices(
        self, odata_filter: str = "(computerDnsName ne null) and (isExcluded eq false)"
    ) -> list["MDEDevice"]:
        """
        Gets a list of all devices from Microsoft Defender for Endpoint.

        This might takes multiples requests, because Microsoft Defender for Endpoint
        only allows to fetch 10K devices at a time.

        params:
            odata_filter:
                str: An OData filter to filter the devices.

        returns:
            list["MDEDevice"]: The machines from Microsoft Defender for Endpoint.
        """

        devices_url = (
            "https://api.securitycenter.microsoft.com/api/machines?$filter={}".format(
                odata_filter
            )
        )
        devices: list["MDEDevice"] = []

        while devices_url:
            res = requests.get(
                devices_url,
                headers={"Authorization": "Bearer {}".format(self.api_token)},
            )

            if not res.ok:
                status_code = res.status_code
                custom_dimensions = {"status": status_code, "body": res.content}
                logger.error(
                    "Failed to fetch devices from Microsoft Defender for Endpoint.",
                    extra={"custom_dimensions": custom_dimensions},
                )
                break

            json = res.json()

            # Get the new devices from the request.
            new_devices = json.get("value")
            logger.info(
                "Fetched {} new devices from Microsoft Defender for Endpoint.".format(
                    len(new_devices)
                )
            )

            # Turn the JSON payloads from MDE into MDEDevice objects.
            for payload in new_devices:
                try:
                    devices.append(MDEDevice.from_json(payload))
                except ValueError:
                    logger.error(
                        "Couldn't create a new MDEDevice from the payload {}.".format(
                            payload
                        )
                    )

            # The Microsoft Defender API has a limit of 10k devices per request.
            # In case this URL exists, this means that more devices can be fetched.
            # This URL given here can be used to fetch the next devices.
            devices_url = json.get("@odata.nextLink")

        logger.info(
            "Fetched a total of {} devices from Microsoft Defender for Endpoint.".format(
                len(devices),
            )
        )

        return devices

    def alter_device_tag(
        self, device: "MDEDevice", tag: str, action: str, retry=True
    ) -> bool:
        """
        Alters a tag for a given device using Microsoft Defender for Endpoint.

        params:
            device:
                MDEDevice: The device to alter the tag from.
            tag:
                str: The tag to alter.
            action:
                str: The actions to perform. Either "Remove" or "Add".
            retry=True:
                bool: True if it should try to fetch request again after 10 seconds if first request fails.

        returns:
            bool: True if it successfully removes the tag otherwise False.
        """

        res = requests.post(
            "https://api.securitycenter.microsoft.com/api/machines/{}/tags".format(
                device.uuid
            ),
            headers={"Authorization": "Bearer {}".format(self.api_token)},
            json={
                "Value": tag,
                "Action": action,
            },
        )

        if not res.ok:
            status_code = res.status_code
            custom_dimensions = {
                "status": status_code,
                "body": res.content,
            }

            if status_code == 429 and retry:
                logger.info(
                    'Could\'t perform action "{}" with tag "{}" on device {}. Retrying after 10 seconds.'.format(
                        action,
                        tag,
                        device,
                    ),
                    extra={"custom_dimensions": custom_dimensions},
                )
                time.sleep(10)
                self.alter_device_tag(tag, action, retry=False)
            else:
                logger.error(
                    'Could\'t perform action "{}" with tag "{}" on device {}.'.format(
                        action,
                        tag,
                        device,
                    ),
                    extra={"custom_dimensions": custom_dimensions},
                )

            return False

        logger.info(
            'Performed action "{}" with tag "{}" on device {}.'.format(
                action, tag, device
            )
        )

        return True

    def get_vulnerabilities(self) -> list["MDEVulnerability"]:
        """
        Get the vulnerabilities of the machine.

        returns:
            list['MDEVulnerability']: The vulnerabilities of the machine.
        """

        kudos_query: str = """
        DeviceTvmSoftwareVulnerabilities
        | where VulnerabilitySeverityLevel == 'Critical'
        | join kind=inner (
            DeviceTvmSoftwareVulnerabilitiesKB
            | where PublishedDate <= datetime_add('day', -25, now())
            | project CveId
        ) on CveId
        | join kind=inner (
            DeviceInfo
            | where IsExcluded == false and isnotempty(OSPlatform)
            | summarize arg_max(Timestamp, *) by DeviceId
            | project-away Timestamp
            | extend MachineInfo = pack(
                'DeviceId', DeviceId,
                'DeviceName', DeviceName,
                'OS', OSPlatform,
                'Tags', parse_json(DeviceManualTags),
                'Users', parse_json(LoggedOnUsers)
            )
        ) on DeviceId
        | summarize Machines = make_set(MachineInfo) by CveId, SoftwareName, SoftwareVendor
        """
        cve_url: str = (
            "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
        )

        vulnerabilities: list["MDEVulnerability"] = []

        while cve_url:
            res = requests.post(
                cve_url,
                headers={"Authorization": "Bearer {}".format(self.api_token)},
                json={"Query": kudos_query},
            )

            if not res.ok:
                status_code = res.status_code
                custom_dimensions = {"status": status_code, "body": res.content}
                logger.error(
                    "Failed to fetch vulnerabilities from Microsoft Defender for Endpoint.",
                    extra={"custom_dimensions": custom_dimensions},
                )
                break

            json = res.json()

            new_vulnerabilities = json.get("Results")
            logger.info(
                "Fetched {} new vulnerabilities from Microsoft Defender for Endpoint.".format(
                    len(new_vulnerabilities)
                )
            )

            for payload in new_vulnerabilities:
                try:
                    vulnerabilities.append(MDEVulnerability.from_json(payload))
                except ValueError:
                    logger.error(
                        "Couldn't create a new MDEVuln from the payload {}.".format(
                            payload
                        )
                    )

            # The Microsoft Defender API has a limit of 8k rows per request.
            # In case this URL exists, this means that more rows can be fetched.
            # This URL given here can be used to fetch the next devices.
            cve_url = json.get("@odata.nextLink")

        logger.info(
            "Fetched a total of {} devices from Microsoft Defender for Endpoint.".format(
                len(vulnerabilities),
            )
        )

        return vulnerabilities

    def get_device_recommendations(
        self,
        device: "MDEDevice",
        odata_filter="remediationType eq 'Update'",
    ) -> list[str]:
        recommendations = []

        recommendation_url: str = "https://api-eu.securitycenter.microsoft.com/api/machines/{}/recommendations?$filter={}".format(
            device.uuid, odata_filter
        )

        while recommendation_url:
            res = requests.get(
                recommendation_url,
                headers={"Authorization": "Bearer {}".format(self.api_token)},
            )

            if not res.ok:
                custom_dimensions = {
                    "status": res.status_code,
                    "body": res.content,
                    "device": device,
                }
                logger.error(
                    "Failed to fetch recommendations for device {} from Microsoft Defender for Endpoint.".format(
                        device
                    ),
                    extra={"custom_dimensions": custom_dimensions},
                )
                break

            json = res.json()

            new_recommendations = json.get("value")
            logger.info(
                "Fetched {} new recommendations from Microsoft Defender for Endpoint.".format(
                    len(new_recommendations)
                )
            )

            for recommendation in new_recommendations:
                name = recommendation.get("recommendationName")
                if name:
                    recommendations.append(name)

            recommendation_url = json.get("@odata.nextLink")

        logger.info(
            "Fetched a total of {} recommendation for device {} from Microsoft Defender for Endpoint.".format(
                len(recommendations), device
            )
        )

        return recommendations


class MDEDevice:
    """
    A class that represents a Microsoft Defender for Endpoint client.

    See below for the class schema properties:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/machine?view=o365-worldwide#properties
    """

    uuid: str
    name: None | str
    health: None | str
    os: None | str
    users: list[str]
    tags: list[str]

    def __init__(
        self,
        uuid: str,
        name: None | str = None,
        health: None | str = None,
        os: None | str = None,
        users: list[str] = [],
        tags: list[str] = [],
    ) -> "MDEDevice":
        """
        Create a new Microsoft Defender for Endpoint device.

        params:
            uuid:
                str: The UUID of the Microsoft Defender for Endpoint device.
            name=None:
                str: The name of the Microsoft Defender for Endpoint device.
                None: No name is provided.
            health=None:
                str: The health of the Microsoft Defender for Endpoint device.
                None: No health status is provided.
            users=[]:
                users[str]: A list of users that used the machine.
            tags=[]:
                list[str]: The tags of the Microsoft Defender for Endpoint device.

        returns:
            MDEDevice: The Microsoft Defender for Endpoint device.
        """
        self.uuid = uuid
        self.name = name
        self.health = health
        self.os = os
        self.users = users
        self.tags = tags

    def __str__(self) -> str:
        """
        The device represented as a string.
        """
        if self.name:
            return '"{}" (UUID="{}")'.format(self.name, self.uuid)
        else:
            return '"UUID={}"'.format(self.uuid)

    def __eq__(self, other: "MDEDevice") -> bool:
        """
        Two devices are equal if they have the same UUID.

        params:
            other: The device to compare against.
        """
        return self.uuid == other.uuid

    def __ne__(self, other: "MDEDevice") -> bool:
        return not self.__eq__(self, other)

    def from_json(json: dict) -> "MDEDevice":
        """
        Create a MDEDevice from a JSON payload.
        """
        return MDEDevice(
            json.get("id"),
            name=json.get("computerDnsName"),
            tags=json.get("machineTags"),
            health=json.get("health"),
            os=json.get("osPlatform"),
        )

    def should_skip(self, automations: list[str], cve: None | str = None) -> bool:
        """
        Returns True if this device should be skipped.

        Automation names:
            DDC2: The Data Defender task 2 (Cleanup FixIt tags).
            DDC3: The Data Defender task 3 (Cleanup ZZZ tags).
            CVE: The CVE automation that create tickets for vulnerable devices.
            CVE-SPECIFIC: Checks if it should skip specific CVE's.

        params:
            automation_names=[]:
                list[str]: The name of the automation to skip. The names can be found above.

        returns:
            bool: True if the device should be skipped.
        """

        patterns: list[re.Pattern] = []

        for automation in automations:
            match automation:
                case "DDC2":
                    patterns.append((0, re.compile(r"^SKIP-DDC2$")))
                case "DDC3":
                    patterns.append((1, re.compile(r"^SKIP-DDC3$")))
                case "CVE":
                    patterns.append((2, re.compile(r"^SKIP-CVE$")))
                case "CVE-SPECIFIC":
                    patterns.append(
                        (3, re.compile(r"^SKIP-CVE-\[(?P<CVE>\*|CVE-\d{4}-\d{4,7})\]$"))
                    )
                case _:
                    logger.warn(
                        'The automation "{}" is not recognized and can therefore not be skipped.'.format(
                            automation
                        )
                    )

        for tag in self.tags:
            for i, pattern in patterns:
                if m := re.match(pattern, tag):
                    match i:
                        # Special logic for pattern 3
                        case 3:
                            groups = m.groupdict()
                            cve_from_tag = groups.get("CVE")
                            if cve_from_tag != cve and cve_from_tag != "*":
                                continue

                    return True

        return False


class MDEVulnerability:
    """
    A class that represents a Microsoft Defender for Endpoint vulnerability.
    """

    uuid: str
    devices: list["MDEDevice"]
    cveId: None | str
    description: None | str
    softwareName: None | str
    softwareVendor: None | str

    def __init__(
        self,
        uuid: str,
        devices: list["MDEDevice"] = [],
        cveId: None | str = None,
        description: None | str = None,
        softwareName: None | str = None,
        softwareVendor: None | str = None,
    ) -> "MDEVulnerability":
        """
        Create a new Microsoft Defender for Endpoint vulnerability.

        params:
            cveId=None:
                str: The UUID of the Microsoft Defender for Endpoint vulnerability.
                None: Not CVE ID is provided.
            description=None:
                None: No description provided.
                str: The vulnerability description.
            devices=[]:
                list[MDEDevice]: The devices that are affected by the vulnerability.
            softwareName=None:
                str: The name of the software vulnerable.
                None: No software name provided.
            softwareVendor=None:
                str: The vendor of the software vulnerable.
                None: No software vendor provided.


        returns:
            MDEVulnerability: The Microsoft Defender Vulnerability.
        """
        self.cveId = cveId
        self.description = description
        self.devices = devices
        self.softwareName = softwareName
        self.softwareVendor = softwareVendor

    def __str__(self):
        """
        The vulnerability represented as a string.
        """
        if len(self.devices) > 5:
            return '"{}" (TotalDevices: {})'.format(self.cveId, len(self.devices))
        else:
            return '"{}"'.format(self.cveId)

    def __eq__(self, other: "MDEVulnerability"):
        return self.cveId == other.cveId

    def __ne__(self, other: "MDEVulnerability"):
        return not self.__eq__(other)

    def from_json(json: dict) -> "MDEDevice":
        """
        Create a MDEVuln from a JSON payload.
        """
        devices: list["MDEDevice"] = []

        machines = json.get("Machines")

        for payload in machines:
            devices.append(
                MDEDevice(
                    payload.get("DeviceId"),
                    name=payload.get("DeviceName") or "Unknown",
                    os=payload.get("OS") or "Unknown",
                    users=payload.get("LoggedOnUsers") or [],
                    tags=payload.get("Tags") or [],
                )
            )

        return MDEVulnerability(
            json.get("id"),
            cveId=json.get("CveId"),
            devices=devices,
            description=json.get("VulnerabilityDescription"),
            softwareName=json.get("SoftwareName"),
            softwareVendor=json.get("SoftwareVendor"),
        )
