"""
All functions and classes related to FixIt 4me.
"""

import logging
import re
from typing import Any, Optional

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
    ) -> Optional[Any]:
        """
        Create a FixIt request in the FixIt 4me account.

        params:
            subject:
                str: The subject of the FixIt request.
            **kwargs:
                dict: The other parameters to pass to the FixIt 4me API.

        returns:
            dict: The JSON response of the created request.
        """
        payload = {"subject": subject}

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

        res.raise_for_status()

        return res.json()

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=4),
        retry=retry_if_exception_type(requests.HTTPError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        retry_error_callback=lambda _: None,
        reraise=True,
    )
    def list_requests(self, query_filter: Optional[str] = None) -> Optional[list]:
        """
        Returns a list of all FixIt requests in the FixIt 4me account.

        params:
            query_filter:
                str: The query filter to apply to the request.
        
        returns:
            list: The list of FixIt requests.
            None: None if the requests couldn't be retrived
        """
        all_requests = []

        query_filter = f"?{query_filter}" if query_filter else ""
        url = f"{self.base_url}/requests/open{query_filter}"

        while url:
            res = requests.get(
                url,
                headers={
                    "X-4me-Account": self.fixit_4me_account,
                    "Authorization": f"Bearer {self.api_key}",
                },
                timeout=300,
            )

            res.raise_for_status()

            all_requests.extend(res.json())

            url = next((
                link["url"] for link in
                requests.utils.parse_header_links(res.headers.get("Link") or "")
                if link["rel"] == "next"
            ), None)

        return all_requests
