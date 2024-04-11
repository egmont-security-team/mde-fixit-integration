import re

import requests

from lib.logging import logger


class FixItClient:
    api_key: str
    base_url: str
    fixit_4me_account: str

    def __init__(self, api_key: str, base_url: str, fixit_4me_account: str):
        self.api_key = api_key

    def extract_id(string: str) -> str:
        """
        Gets the FixIt request ID from a given string if it is a prober FixIt tag.
        This uses regular expression to determine if the tag is prober.

        params:
            tag:
                str: The tag to get the FixIt request ID from.

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
            fixit_4me_account:
                str: The FixIt 4me account to find the request in.
            api_key:
                str: The api key used for authorizing with FixIt 4me REST api.

        returns:
            The status of the request.
        """

        res = requests.get(
            format("%s/requests/%s", self.base_url, request_id),
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": format("Bearer %s", self.api_key),
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
                    format('The request "%s" was not found in the FixIt 4me account.', request_id),
                    extra={"custom_dimensions": custom_dimensions},
                )
            else:
                logger.error(
                    format('Could not get the request "%s" from the FixIt 4me REST API.', request_id),
                    extra={"custom_dimensions": custom_dimensions},
                )

            return ""

        return json.get("status")
