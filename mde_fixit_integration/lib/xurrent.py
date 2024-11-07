"""All functions and classes related to Xurrent (4me)."""

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


class XurrentClient:
    """A client that can interact with the Xurrent API."""

    base_url: str
    xurrent_account: str
    api_key: str

    def __init__(
        self,
        base_url: str,
        xurrent_account: str,
        api_key: str,
    ) -> None:
        """
        Create a new client to interact with the Xurrent (4me) API.

        Parameters
        ----------
        base_url : str
            Base URL of the Xurrent REST API.
        xurrent_account : str
            Xurrent account to use.
        api_key : str
            API key to use for the Xurrent client.

        """
        self.base_url = base_url
        self.xurrent_account = xurrent_account
        self.api_key = api_key

    @staticmethod
    def extract_id(string: str) -> Optional[str]:
        """
        Extract a ticket ID from a string.

        Gets the ticket ID from a given string (if it's a prober ticket tag).
        This uses regular expression to find the tag.

        Parameters
        ----------
        string : str
            The string to extract the ticket ID from.

        Returns
        -------
        str
            The ticket ID from the tag.

        """
        # If this regular expression does not match, it is not a ticket tag.
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
    def get_ticket_status(self, ticket_id: str) -> str:
        """
        Get the status of a ticket.

        Parameters
        ----------
        ticket_id : str
            Ticket ID of the ticket to check (e.g #9999999).

        Returns
        -------
        str
            The status of the ticket.

        """
        res = requests.get(
            f"{self.base_url}/requests/{ticket_id}",
            headers={
                "X-4me-Account": self.xurrent_account,
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
    def create_ticket(
        self,
        subject: str,
        **kwargs,
    ) -> Any:
        """
        Create a ticket.

        Parameters
        ----------
        subject : str
            Subject of the ticket.
        **kwargs : dict
            Other parameters to pass to the ticket.

        Returns
        -------
        any
            JSON object of the response.

        """
        payload = {"subject": subject}

        payload.update(kwargs)

        res = requests.post(
            f"{self.base_url}/requests",
            headers={
                "X-4me-Account": self.xurrent_account,
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
    def list_tickets(self, query_filter: Optional[str] = None) -> list[Any]:
        """
        Get a list of all tickets in the account.

        Parameters
        ----------
        query_filter : str
            Query filter to apply to the request.

        Returns
        -------
        list[Any]
            The list of tickets.

        """
        all_tickets = []

        query_filter = f"?{query_filter}" if query_filter else ""
        url = f"{self.base_url}/requests/open{query_filter}"

        while url:
            res = requests.get(
                url,
                headers={
                    "X-4me-Account": self.xurrent_account,
                    "Authorization": f"Bearer {self.api_key}",
                },
                timeout=300,
            )

            res.raise_for_status()

            all_tickets.extend(res.json())

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

        return all_tickets

    def get_attachments_storage(self) -> Any:
        """
        Get the attachment storage information.

        Returns
        -------
        Any
            Storage information for attachments.

        """
        res = requests.get(
            f"{self.base_url}/attachments/storage",
            headers={
                "X-4me-Account": self.xurrent_account,
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
            File path of file to upload.

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
