"""
All functions and classes related to FixIt 4me.
"""

import re

import requests

from lib.logging import logger
from lib.mde import MDEDevice, MDEVulnerability


class FixItClient:
    """
    A FixIt client that can interact with the FixIt API.
    """

    base_url: str
    fixit_4me_account: str
    api_key: str

    def __init__(
        self,
        base_url: str,
        fixit_4me_account: str,
        api_key: str,
    ) -> "FixItClient":
        """
        Create a new FixIt client to interact with the FixIt API.

        params:
            base_url:
                str: The base URL of the FixIt 4me REST API.
            fixit_4me_account:
                str: The FixIt 4me account to use.
            api_key:
                str: The API key to use for the FixIt client.

        returns:
            FixItClient: The FixIt client.
        """
        self.base_url = base_url
        self.fixit_4me_account = fixit_4me_account
        self.api_key = api_key

    def extract_id(string: str) -> str:
        """
        Gets the FixIt request ID from a given string (if it's a prober FixIt tag).
        This uses regular expression to determine if the tag is prober.

        params:
            string:
                str: The string to get the FixIt request ID from.

        returns:
            str: The FixIt request ID from the tag.
        """

        # If this regular expression does not match, it is not a FixIt tag.
        # This also takes care of human error by checking for spaces between
        # the "#" and the numbers
        if not re.match(r"^#( )*[0-9]+$", string):
            return ""

        # This removes the "#" and optional spaces from the tag.
        return re.sub(r"^#( )*", "", string)

    def get_fixit_request_status(self, request_id: str) -> str:
        """
        Gets the status of the FixIt request relative to the request id given.

        params:
            request_id:
                str: The request id of the request to check.

        returns:
            str: The status of the request.
        """

        res = requests.get(
            f"{self.base_url}/requests/{request_id}",
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        if not res.ok:
            status_code = res.status_code
            custom_dimensions = {
                "base_url": self.base_url,
                "X-4me-Account": self.fixit_4me_account,
                "status": status_code,
                "body": res.content,
            }

            if status_code == 404:
                logger.error(
                    f'The request "{request_id}" was not found in the FixIt 4me account.',
                    extra={"custom_dimensions": custom_dimensions},
                )
            else:
                logger.error(
                    f'Could not get the request "{request_id}" from the FixIt 4me REST API.',
                    extra={"custom_dimensions": custom_dimensions},
                )

            return ""

        return res.json().get("status")

    def create_single_device_fixit_requests(
        self, device: MDEDevice, vulnerability: MDEVulnerability, recommendations: str
    ) -> str:
        """
        Create a FixIt request in the FixIt 4me account.

        params:
            device:
                MDEDevice: The device to create a vulnerability request for.

            vulnerability:
                MDEVulnerability: The vulnerablility affecting the device.

            recommendations:
                str: The security recommendations to fix the vulnerability (and other stuff on the device).

        returns:
            str: The ID of the created request.
        """

        payload = {
            "subject": f"Security[{vulnerability.cveId}]: Vulnerable Device",
            # The template ID from FixIt.
            "template_id": "186253",
            # Custom template fields.
            "custom_fields": [
                {"id": "cve", "value": vulnerability.cveId or vulnerability.uuid},
                {
                    "id": "software_name",
                    "value": vulnerability.softwareName or "Unknown",
                },
                {
                    "id": "software_vendor",
                    "value": vulnerability.softwareVendor or "Unknown",
                },
                {"id": "device_name", "value": device.name},
                {"id": "device_uuid", "value": device.uuid},
                {"id": "device_os", "value": device.os},
                {"id": "device_users", "value": ", ".join(device.users) or "Unknown"},
                {
                    "id": "recommended_security_updates",
                    "value": "\n".join(recommendations),
                },
            ],
        }
        res = requests.post(
            f"{self.base_url}/requests",
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": f"Bearer {self.api_key}",
            },
            json=payload,
        )

        if not res.ok:
            status_code = res.status_code
            custom_dimensions = {
                "base_url": self.base_url,
                "X-4me-Account": self.fixit_4me_account,
                "status": status_code,
                "body": res.content,
            }

            if status_code == 404:
                logger.error(
                    "Couldn't find the FixIt 4me template",
                    extra={"custom_dimensions": custom_dimensions},
                )
            elif status_code == 401:
                logger.error(
                    "Unauthorized for creating the FixIt 4me request",
                    extra={"custom_dimensions": custom_dimensions},
                )
            else:
                logger.error(
                    "Couldn't create the FixIt 4me request.",
                    extra={"custom_dimensions": custom_dimensions},
                )

            return ""

        return res.json().get("id")
