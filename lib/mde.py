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

        status_code = res.status_code
        json = res.json()

        if status_code != 200:
            custom_dimensions = {"status": status_code, "body": res.content}
            logger.error(
                "Couldn't get Microsoft Defender token from Microsoft authentication flow.",
                extra={"custom_dimensions": custom_dimensions},
            )
            return ""

        token = json.get("access_token")

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

            status_code = res.status_code
            json = res.json()

            if status_code != 200:
                custom_dimensions = {"status": status_code, "body": res.content}
                logger.error(
                    "Failed to fetch devices from Microsoft Defender for Endpoint.",
                    extra={"custom_dimensions": custom_dimensions},
                )
                break

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
                device.device_id
            ),
            headers={"Authorization": "Bearer {}".format(self.token)},
            json={
                "Value": tag,
                "Action": action,
            },
        )

        status_code = res.status_code

        if status_code != 200:
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
                return

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
            'Performed action "{}" with tag "{}" on device.'.format(
                action.tag,
                device,
            )
        )

        return True

    def get_vulnerabilities(self) -> list["MDEVuln"]:
        """
        Get the vulnerabilities of the machine.

        returns:
            list['MDEVuln']: The vulnerabilities of the machine.
        """

        kudos_query: str = """
        DeviceTvmSoftwareVulnerabilities
        | where VulnerabilitySeverityLevel == 'Critical'
        | join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
        | where PublishedDate <= datetime_add('day', -25, now())
        | join kind=leftouter DeviceInfo on DeviceId
        | where IsExcluded == false
        | project CveId, DeviceId, DeviceName, DeviceManualTags, LoggedOnUsers, VulnerabilityDescription
        | extend MachineInfo = pack('DeviceId', DeviceId, 'DeviceName', DeviceName, 'Tags', DeviceManualTags, 'LoggedOnUsers', LoggedOnUsers)
        | summarize Machines = make_set(MachineInfo) by CveId, VulnerabilityDescription
        | extend TotalMachines = array_length(Machines)
        | order by TotalMachines desc
        """
        cve_url: str = (
            "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
        )

        vulnerabilities: list["MDEVuln"] = []

        while cve_url:
            res = requests.post(
                cve_url,
                headers={"Authorization": "Bearer {}".format(self.api_token)},
                json={"Query": kudos_query},
            )

            status_code = res.status_code
            json = res.json()

            if status_code != 200:
                custom_dimensions = {"status": status_code, "body": res.content}
                logger.error(
                    "Failed to fetch vulnerabilities from Microsoft Defender for Endpoint.",
                    extra={"custom_dimensions": custom_dimensions},
                )
                break

            new_vulnerabilities = json.get("Results")
            logger.info(
                "Fetched {} new vulnerabilities from Microsoft Defender for Endpoint.".format(
                    len(new_vulnerabilities)
                )
            )

            for payload in new_vulnerabilities:
                try:
                    vulnerabilities.append(MDEVuln.from_json(payload))
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


class MDEDevice:
    """
    A class that represents a Microsoft Defender for Endpoint client.

    See below for the class schema properties:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/machine?view=o365-worldwide#properties
    """

    uuid: str
    name: None | str
    tags: list[str]
    health: None | str

    def __init__(
        self,
        uuid: str,
        name: None | str = None,
        tags: list[str] = [],
        health: None | str = None,
    ) -> "MDEDevice":
        """
        Create a new Microsoft Defender for Endpoint device.

        params:
            uuid:
                str: The UUID of the Microsoft Defender for Endpoint device.
            name=None:
                str: The name of the Microsoft Defender for Endpoint device.
                None: No name is provided.
            tags=[]:
                list[str]: The tags of the Microsoft Defender for Endpoint device.
            health=None:
                str: The health of the Microsoft Defender for Endpoint device.
                None: No health status is provided.

        returns:
            MDEDevice: The Microsoft Defender for Endpoint device.
        """
        self.uuid = uuid
        self.name = name
        self.tags = tags
        self.health = health

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
        Two devices are equal if their UUID is the same.

        params:
            other: The device to compare against.
        """
        return self.uuid == other.uuid

    def __ne__(self, other: "MDEDevice") -> bool:
        return not self.__eq__(self, other)

    def from_json(json: str) -> "MDEDevice":
        """
        Create a MDEDevice from a JSON payload.
        """
        return MDEDevice(
            json.get("id"),
            name=json.get("computerDnsName"),
            tags=json.get("machineTags"),
            health=json.get("health"),
        )

    def should_skip(self, automation_names: list[str], cve: None | str = None) -> bool:
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

        for automation in automation_names:
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
                    # Special logic for pattern 3
                    if i == 3:
                        groups = m.groupdict()
                        cve_from_tag = groups.get("CVE")
                        if cve_from_tag != cve and cve_from_tag != "*":
                            continue
                    return True

        return False


class MDEVuln:
    """
    A class that represents a Microsoft Defender for Endpoint vulnerability.
    """

    cveId: str
    description: str
    devices: list["MDEDevice"]
    totalDevices: int

    def __init__(
        self,
        cveId: str,
        description: None | str = None,
        devices: list["MDEDevice"] = [],
        totalDevices: None | int = None,
    ) -> "MDEVuln":
        """
        Create a new Microsoft Defender for Endpoint vulnerability.

        params:
            cveId:
                str: The UUID of the Microsoft Defender for Endpoint vulnerability.
            description=None:
                None: No description provided.
                str: The vulnerability description.
            devices=[]:
                list[MDEDevice]: The devices that are affected by the vulnerability.
            totalDevices=None:
                None: No total of devices provided.
                int: The number of devices.

        returns:
            MDEVuln: The Microsoft Defender Vulnerability.
        """

        self.cveId = cveId
        self.description = description
        self.devices = devices
        self.totalDevices = totalDevices

    def from_json(json: str) -> "MDEDevice":
        """
        Create a MDEVuln from a JSON payload.
        """
        devices: list["MDEDevice"] = []

        machines = json.get("Machines")

        for payload in machines:
            devices.append(
                MDEDevice(
                    payload.get("DeviceId"),
                    name=payload.get("DeviceName"),
                    tags=payload.get("Tags"),
                )
            )

        return MDEVuln(
            json.get("CveId"),
            description=json.get("VulnerabilityDescription"),
            devices=devices,
            totalDevices=json.get("TotalMachines"),
        )

    def __str__(self):
        """
        The vulnerability represented as a string.
        """
        if len(self.devices) > 0:
            return '"{}" (TotalDevices: {})'.format(self.cveId, self.totalDevices)
        else:
            return '"{}"'.format(self.cveId)
