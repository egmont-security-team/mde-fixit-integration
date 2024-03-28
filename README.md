# MDE FixIt Integration

A Azure Function that uses data from Microsoft Defender and FixIt to automate certain tasks descried in the [Automation](#automation) sections.

## Automation

- [Inactive Devices](#inactive-devices): Adds `ZZZ` tags to duplicate devices in Defender Portal.

- [Cleanup FixIt Tags](#cleanup-fixit-tags): Removes FixIt tags from completed FixIt requests.

- [Critical Exposure Requests](#critical-exposure-requests): Create a FixIt request for devices hit by a `critical` exposure CVE.

- [High Exposure Requests](#high-exposure-requests): Create a FixIt request for devices hit by a `high` exposure CVE after 25 days.

### Detailed description

#### Inactive Devices

Runs: On business days.

Checks if the device name is found multiple times in the Defender Portal. If the device does exists multiple times, we make sure it is inactive and then add the `ZZZ` tag to the devices.

#### Cleanup FixIt tags

Runs: On business days.

This checks all devices for FixIt tags and then checks if the referenced tag is closed in the FixIt portal. If the FixIt request referenced by the tag on the device is closed, the tag is removed from the device.

#### Critical Exposure Requests

Runs: unknown.

#### High Exposure Requests

Runs: unknown.

## Configuration

- You can set the environment variable `KEY_VAULT_NAME` to change what key vault will be used to load secrets.
