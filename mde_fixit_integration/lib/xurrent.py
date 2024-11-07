"""All functions and classes related to Xurrent (4me)."""

import logging
import re
from pathlib import Path
import time
from typing import Any, Callable, Optional

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
    api_token: str

    def __init__(
        self,
        base_url: str,
        xurrent_account: str,
        api_token: str,
    ) -> None:
        """
        Create a new client to interact with the Xurrent (4me) API.

        Parameters
        ----------
        base_url : str
            Base URL of the Xurrent REST API.
        xurrent_account : str
            Xurrent account to use.
        api_token : str
            API key to use for the Xurrent client.

        """
        self.base_url = base_url
        self.xurrent_account = xurrent_account
        self.api_token = api_token

    def _make_request(
        self,
        endpoint: str,
        method: Callable[..., requests.Response],
        authorized_endpoint: bool = True,
        **kwargs,
    ) -> requests.Response:
        headers = {
            "X-4me-Account": self.xurrent_account,
        } 

        if authorized_endpoint:
            headers["Authorization"] = f"Bearer {self.api_token}"

        if extra_headers := kwargs.pop("headers", None):
            headers.update(extra_headers)

        url = f"{self.base_url}{endpoint}"

        res = method(url, headers, **kwargs)

        if delay := res.headers.get("Retry-After"):
            time.sleep(int(delay))

            return self._make_request(
                url,
                method,
                authorized_endpoint,
                **kwargs,
            )

        res.raise_for_status()

        return res

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
        res = self._make_request(
            f"/requests/{ticket_id}",
            requests.get,
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

        res = self._make_request(
            f"/requests",
            requests.post,
            timeout=300,
            json=payload,
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
        endpoint = f"/requests/open"

        while url:
            res = self._make_request(
                f"{endpoint}{query_filter}",
                requests.get,
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
        res = self._make_request(
            f"/attachments/storage",
            requests.get,
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

            # This is not a Xurrent API endpoint and does
            # therefore not use "self._make_requests()"
            res = requests.post(
                storage["upload_uri"],
                timeout=300,
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
            )

            res.raise_for_status()

            xml = xmltodict.parse(res.content)
            return xml["PostResponse"]["Key"]
