"""
All functions and classes related to FixIt 4me.
"""

import re

import requests

from lib.logging import logger


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
            api_key:
                str: The API key to use for the FixIt client.
            base_url:
                str: The base URL of the FixIt 4me REST API.
            fixit_4me_account:
                str: The FixIt 4me account to use.

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
        if not re.match(r"#( )*[0-9]+", string):
            return ""

        # This removes the "#" and optional spaces from the tag.
        return re.sub(r"#( )*", "", string)

    def get_fixit_request_status(self, request_id: str) -> str:
        """
        Gets the status of the FixIt request relative to the request id given.

        params:
            request_id:
                str: The request id of the request to check.

        returns:
            The status of the request.
        """

        res = requests.get(
            "{}/requests/{}".format(self.base_url, request_id),
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": "Bearer {}".format(self.api_key),
            },
        )

        status_code = res.status_code
        json = res.json()

        if status_code != 200:
            custom_dimensions = {
                "base_url": self.base_url,
                "X-4me-Account": self.fixit_4me_account,
                "status": status_code,
                "body": res.content,
            }

            if status_code == 404:
                logger.error(
                    'The request "{}" was not found in the FixIt 4me account.'.format(
                        request_id
                    ),
                    extra={"custom_dimensions": custom_dimensions},
                )
            else:
                logger.error(
                    'Could not get the request "{}" from the FixIt 4me REST API.'.format(
                        request_id
                    ),
                    extra={"custom_dimensions": custom_dimensions},
                )

            return ""

        return json.get("status")
