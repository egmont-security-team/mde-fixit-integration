import re

import requests

from src.logging import logger


def get_fixit_request_id_from_tag(tag: str) -> str:
    """
    Gets the FixIt request ID from a given tag if it is a prober FixIt tag.
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
    if not re.match(r"#( )*[0-9]+", tag):
        return ""

    # This removes the # and the spaces from the tag.
    return re.sub(r"#( )*", "", tag)


def get_fixit_request_status(
    request_id: str, fixit_4me_account: str, api_key: str
) -> str:
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
        f"https://api.4me.com/v1/requests/{request_id}",
        headers={
            "X-4me-Account": fixit_4me_account,
            "Authorization": f"Bearer {api_key}",
        },
    )

    status_code = res.status_code
    json = res.json()

    if status_code != 200:
        custom_dimensions = {
            "X-4me-Account": fixit_4me_account,
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

    return json.get("status")


def alter_device_tag(token: str, device_id: str, tag: str, action: str) -> bool:
    """
    Alters a tag from a given device in the defender portal.

    params:
        token:
            str: The bearer token to authorize with the Microsoft Defender API.
        device_id:
            str: The id of the device to remove the tag from.
        tag:
            str: The to remove from the machine.
        action:
            str: The actions to perform. Either "Remove" or "Add".

    returns:
        bool: True if it successfully removes the tag otherwise False.
    """

    res = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{device_id}/tags",
        json={
            "Value": f"{tag}",
            "Action": "Remove",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    status_code = res.status_code

    if status_code != 200:
        custom_dimensions = {
            "status": status_code,
            "body": res.content,
        }
        logger.error(
            f'Could\'t perform action "{action}" with tag "{tag}" on device with ID "{device_id}".',
            extra={"custom_dimensions": custom_dimensions},
        )
        return False

    logger.info(
        f'Performed action "{action}" with tag "{tag}" on device with ID "{device_id}".'
    )

    return True
