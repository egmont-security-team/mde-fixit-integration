"""All functions and classes related to FixIt Xurrent (4me)."""

import logging
import re
from pathlib import Path
from typing import Any, Optional

import requests
import xmltodict
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)


class FixItClient:
    """A client that can interact with the FixIt API."""

    base_url: str
    fixit_4me_account: str
    api_key: str

    def __init__(
        self,
        base_url: str,
        fixit_4me_account: str,
        api_key: str,
    ) -> None:
        """
        Create a new client to interact with the FixIt API.

        Parameters
        ----------
        base_url : str
            The base URL of the FixIt 4me REST API.
        fixit_4me_account : str
            The FixIt 4me account to use.
        api_key : str
            The API key to use for the FixIt client.

        """
        self.base_url = base_url
        self.fixit_4me_account = fixit_4me_account
        self.api_key = api_key

    @staticmethod
    def extract_id(string: str) -> Optional[str]:
        """
        Extra a request ID from a string.

        Gets the FixIt request ID from a given string (if it's a prober FixIt tag).
        This uses regular expression to find the tag.

        Parameters
        ----------
        string : str
            The string to extract the FixIt request ID from.

        Returns
        -------
        str
            The FixIt request ID from the tag.

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
    def get_request_status(self, request_id: str) -> str:
        """
        Get the status of a request.

        Parameters
        ----------
        request_id : str
            The request id of the request to check (e.g #9999999).

        Returns
        -------
        str
            The status of the request.

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
    ) -> Any:
        """
        Create a request.

        Parameters
        ----------
        subject : str
            Subject of the request.
        **kwargs : dict
            Other parameters to pass to the request.

        Returns
        -------
        any
            The JSON object of the response.

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
    def list_requests(self, query_filter: Optional[str] = None) -> list[Any]:
        """
        Get a list of all requests in the account.

        Parameters
        ----------
        query_filter : str
            Query filter to apply to the request.

        Returns
        -------
        list[Any]
            The list of requests.

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

            url = next(
                (
                    link["url"]
                    for link in requests.utils.parse_header_links(
                        res.headers.get("Link") or "",
                    )
                    if link["rel"] == "next"
                ),
                None,
            )

        return all_requests

    def get_attachments_storage(self) -> Any:
        """
        Get the attachment storage information.

        Returns
        -------
        Any
            The storage information for the FixIt attachments.

        """
        res = requests.get(
            f"{self.base_url}/attachments/storage",
            headers={
                "X-4me-Account": self.fixit_4me_account,
                "Authorization": f"Bearer {self.api_key}",
            },
            timeout=300,
        )

        res.raise_for_status()

        return res.json()

    def upload_file(self, file_path: str) -> str:
        """
        Upload a file to attachment storage.

        Parameters
        ----------
        file_path : str
            The file to upload.

        Returns
        -------
        str
            The key of the uploaded file.

        """
        with Path(file_path).open("rb") as file:
            storage = self.get_attachments_storage()
            s3 = storage["s3"]

            file_name = file_path.split("/")[-1]

            res = requests.post(
                storage["upload_uri"],
                files={
                    "Content-Type": (None, "text/csv"),
                    "acl": (None, s3["acl"]),
                    "key": (None, s3["key"]),
                    "policy": (None, s3["policy"]),
                    "success_action_status": (None, s3["success_action_status"]),
                    "x-amz-algorithm": (None, s3["x-amz-algorithm"]),
                    "x-amz-credential": (None, s3["x-amz-credential"]),
                    "x-amz-date": (None, s3["x-amz-date"]),
                    "x-amz-server-side-encryption": (None, s3["x-amz-server-side-encryption"]),  # noqa: E501
                    "x-amz-signature": (None, s3["x-amz-signature"]),
                    "file": (file_name, file, "text/csv"),
                },
                timeout=300,
            )

            res.raise_for_status()

            xml = xmltodict.parse(res.content)
            return xml["PostResponse"]["Key"]
