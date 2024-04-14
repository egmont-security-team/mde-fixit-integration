"""
All functions and classes related to Microsoft Defender for Endpoint.
"""

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
    ):
        """
        Create a new Micosoft Defender for Endpoint client to interact with the MDE API.
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
            f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.secret_value,
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

        return token

    def get_devices(self) -> list["MDEDevice"]:
        """
        Gets a list of all devices from Microsoft Defender for Endpoint.

        This might takes multiples requests, because Microsoft Defender for Endpoint
        only allows to fetch 10K devices at a time.

        returns:
            list['MDEDevice']: The machines from Microsoft Defender for Endpoint.
        """

        devices_url = "https://api.securitycenter.microsoft.com/api/machines?$filter=(computerDnsName ne null) and (isExcluded eq false)"
        devices = []

        while devices_url:
            res = requests.get(
                devices_url, headers={"Authorization": format("Bearer %s", self.token)}
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
                format(
                    "Fetched %d new devices from Microsoft Defender for Endpoint.",
                    len(new_devices),
                )
            )

            devices += new_devices

            # The Microsoft Defender API has a limit of 10k devices per request.
            # In case this URL exists, this means that more devices can be fetched.
            # This URL given here can be used to fetch the next devices.
            devices_url = json.get("@odata.nextLink")

        logger.info(
            format(
                "Fetched a total of %d devices from Microsoft Defender for Endpoint.",
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
            format(
                "https://api.securitycenter.microsoft.com/api/machines/%s/tags",
                self.device_id,
            ),
            headers={"Authorization": format("Bearer %s", self.token)},
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
                    format(
                        """
                        Could\'t perform action "%s" with tag "%s" on device %s. Retrying after 10 seconds.
                        """,
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
                format(
                    """
                    Could\'t perform action "%s" with tag "%s" on device %s.'
                    """,
                    action,
                    tag,
                    device,
                ),
                extra={"custom_dimensions": custom_dimensions},
            )
            return False

        logger.info(
            format(
                """
                Performed action "%s" with tag "%s" on device %s.
                """,
                action,
                tag,
                device,
            )
        )

        return True

    def get_machine_vulnrabilities(self):
        high_cve_url_filter = (
            "$filter=(publishedOn lt 2024-03-11T00:00:00Z) and (severity eq 'High')"
        )
        high_cve_url = format(
            "https://api.securitycenter.microsoft.com/api/machines/%s/vulnerabilities?%s",
            self.device_id,
            high_cve_url_filter,
        )

        requests.get(high_cve_url)


class MDEDevice:
    """
    A class that represents a Microsoft Defender for Endpoint client.

    See below for the class schema properties:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/machine?view=o365-worldwide#properties
    """

    uuid: str
    name: None | str
    tags: None | list(str)
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

    def __str__(self):
        if self.uuid:
            return format('"UUID=%s"', self.uuid)
        else:
            return format('"%s" (UUID="%s")', self.name, self.uuid)
