"""
All functions and classes related to Microsoft Defender for Endpoint.
"""

from datetime import datetime, timedelta
import time
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
        Create a new Micosoft Defender for Endpoint client to interact with the MDE API.

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
                str: An OData fitler to filter the devices.

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

            # Turn the JSON paylaods from MDE into MDEDevice objects.
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
        Alters a tag for a given device using Mirosoft Defender for Endpoint.

        params:
            device:
                "MDEDevice": The device to alter the tag from.
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
                self.device_id
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
                    """
                    Could\'t perform action "{}" with tag "{}" on device {}. Retrying after 10 seconds.
                    """.format(
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
                """
                Could\'t perform action "{}" with tag "{}" on device {}.'
                """.format(
                    action,
                    tag,
                    device,
                ),
                extra={"custom_dimensions": custom_dimensions},
            )
            return False

        logger.info(
            """
            Performed action "{}" with tag "{}" on device {}.
            """.format(
                action,
                tag,
                device,
            )
        )

        return True


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

    def get_vulnrabilities(self, kind="high") -> list["MDEVuln"]:
        """
        Get the vulnerabilities of the machine.

        params:
            kind="high":
                str: The kind of vulnerabilities to fetch. Either "high" or "critical".

        returns:
            list['MDEVuln']: The vulnerabilities of the machine.
        """

        if kind == "high":
            lookback_time_filter = (
                (datetime.now() - timedelta(days=24))
                .replace(hour=0, minute=0, second=0, microsecond=0)
                .isoformat()
            )
            cve_url_filter = (
                "$filter=(publishedOn lt {}) and (severity eq 'High')".format(
                    lookback_time_filter,
                )
            )
        elif kind == "critical":
            cve_url_filter = "$filter=severity eq 'Critical'"
        else:
            raise ValueError("The kind parameter must be either 'high' or 'critical'.")

        cve_url = "https://api.securitycenter.microsoft.com/api/machines/{}/vulnerabilities?{}".format(
            self.device_id,
            cve_url_filter,
        )

        while cve_url:
            res = requests.get(
                cve_url, headers={"Authorization": "Bearer {}".format(self.token)}
            )

            json = res.json()

            cve_url = json.get("@odata.nextLink")

    def __str__(self):
        if self.uuid:
            return '"UUID={}"'.format(self.uuid)
        else:
            return '"{}" (UUID="{}")'.format(self.name, self.uuid)


class MDEVuln:
    """
    A class that represents a Microsoft Defender for Endpoint vulnerability.
    """

    uuid: str

    def __init__(self, uuid: str) -> "MDEVuln":
        """
        Create a new Microsoft Defender for Endpoint vulnerability.

        params:
            uuid:
                str: The UUID of the Microsoft Defender for Endpoint vulnerability.
        """
        self.uuid = uuid
