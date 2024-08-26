"""
All functions and classes related to FixIt 4me.
"""

import logging
import re
from typing import Optional

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)


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
    ):
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

    @staticmethod
    def extract_id(string: str) -> Optional[str]:
        """
        Gets the FixIt request ID from a given string (if it's a prober FixIt tag).
        This uses regular expression to determine if the tag is prober.

        params:
            string:
                str: The string to extract the FixIt request ID from.

        returns:
            str: The FixIt request ID from the tag.
        """

        # If this regular expression does not match, it is not a FixIt tag.
        # This also takes care of human error by checking for spaces between
        # the "#" and the numbers
        if not re.fullmatch(r"^#( )*[0-9]+$", string):
            return None

        # This removes the "#" and optional spaces from the tag.
        return re.sub(r"^#( )*", "", string)

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def get_request_status(self, request_id: str) -> Optional[str]:
        """
        Gets the status of the FixIt request relative to the request id given.

        params:
            request_id:
                str: The request id of the request to check (e.g #9999999).

        returns:
            str: The status of the request.
            None: None if the request couldn't be retrived.
        """

        res = requests.get(
            f"{self.base_url}/requests/{request_id}",
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": f"Bearer {self.api_key}",
            },
            timeout=120,
        )

        custom_dimensions = {
            "base_url": self.base_url,
            "X-4me-Account": self.fixit_4me_account,
            "status": res.status_code,
            "body": res.content,
        }

        match res.status_code:
            case 401:
                logger.error(
                    "Unauthorized for fetching the FixIt 4me request status",
                    extra=custom_dimensions,
                )
                return None
            case 404:
                logger.error(
                    f'The request "{request_id}" was not found in the FixIt 4me account.',
                    extra=custom_dimensions,
                )
                return None
            case _:
                res.raise_for_status()

        json = res.json()

        return json["status"]

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def create_request(
        self,
        subject: str,
        **kwargs,
    ) -> Optional[dict]:
        """
        Create a FixIt request in the FixIt 4me account.

        params:
            subject:
                str: The subject of the FixIt request.
            **kwargs:
                dict: The other parameters to pass to the FixIt 4me API.

        returns:
            str: The JSON response of the created request.
        """
        payload = {
            "subject": subject
        }

        payload.update(kwargs)

        res = requests.post(
            f"{self.base_url}/requests",
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": f"Bearer {self.api_key}",
            },
            json=payload,
            timeout=300,
        )

        custom_dimensions = {
            "base_url": self.base_url,
            "X-4me-Account": self.fixit_4me_account,
            "status": res.status_code,
            "payload": str(payload),
            "body": res.content,
        }

        match res.status_code:
            case 401:
                logger.error(
                    "Unauthorized for creating the FixIt 4me request.",
                    extra=custom_dimensions,
                )
                return None
            case 404:
                logger.error(
                    "Couldn't find the FixIt 4me template.",
                    extra=custom_dimensions,
                )
                return None
            case 422:
                logger.error(
                    "Invalid request for creating the FixIt 4me request.",
                    extra=custom_dimensions,
                )
                return None
            case _:
                res.raise_for_status()

        return res.json()
