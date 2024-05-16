# MDE FixIt Integration

A Azure Function that uses data from Microsoft Defender and FixIt to automate certain tasks descried in the [Automation](#automation) sections.

## Automation

- [Cleanup FixIt Tags](#ddc2-cleanup-fixit-tags): Removes FixIt tags from devices if the FixIt requests is completed.

- [Inactive Devices](#ddc3-inactive-devices): Adds `ZZZ` tags to duplicate devices in the Defender Portal.

- [Critical Exposure Tickets](#cve-critical-exposure-tickets): Create a FixIt request for devices hit by a `critical` CVEs.

### Detailed description

#### DDC2: Cleanup FixIt tags

Runs: On weekdays at 8 AM and 2 PM.

Skip tags: `SKIP-DDC2`

This checks all devices for FixIt tags and then checks if the ticket referenced by the tag is completed. If the FixIt request is completed, the tag is removed from the device.

#### DDC3: Inactive Devices

Runs: On weekdays at 6 AM.

Skip tags: `SKIP-DDC3`

Checks if multiple devices have the same name and one of them is inactive. If this is true, then the `ZZZ` tag is added to the device.

#### CVE: Critical Exposure Tickets

Runs: On weekdays at 8 AM.

Skip tags: `SKIP-CVE`, `SKIP-CVE-[CVE-2024-9999]`

This marks all devices hit by critical or high CVEs, older than 25 days. If the device has any recommended application software updates, a FixIt ticket will be automatically opened. CVEs that hit more than a certain [threshold](#configuration) is seen as a multi ticket and one ticket is created for all of the hit devices. If number is under the threshold, it is seen as a single ticket and 1 ticket will be created per device instead. If a device already have a FixIt tag, the device will be skipped.

The FixIt ticket will hold following information:

- The CVE ID and Software name and vendor if know.

- Device Information such as UUID of the device, Users that use it, The OS and Name of the device.

- Recommended Security updates (Only software updates)

## Configuration

Environment variables is set in the Azure Function app in Azure.

- Set the environment variable `KEY_VAULT_NAME` to change what key vault will be used to load secrets.

- TODO: Set the environment variable `DEVICE_THRESHOLD` to change how many devices should be hit by a CVE, before it's seen as a multi ticket in the CVE automation.
