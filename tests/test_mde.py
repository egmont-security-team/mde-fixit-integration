"""
This module contains tests for the MDEDevice class.
"""

from datetime import UTC, datetime
from lib.mde import MDEDevice


def get_devices() -> list[MDEDevice]:
    """
    Returns a list of MDEDevice objects for testing. 
    """
    return [
        # Should NOT be skipped for CVE automation.
        MDEDevice("1", "test1", "Active", "Windows", "Onboarded", ["DAE", "SKIP-DDC2", "SKIP-DDC3"], datetime.now(UTC)),
        # Should be skipped for CVE automation if correct CVE is given.
        MDEDevice("2", "test2", "Active", "Windows", "Onboarded", ["NNH", "SKIP-CVE-[CVE-2021-4104]"], datetime.now(UTC)),
        # Should be skipped for CVE automation if correct CVE is given.
        MDEDevice("3", "test3", "Active", "Windows", "Onboarded", ["NNH", "SKIP-CVE-[CVE-2021-6829]"], datetime.now(UTC)),
        # Should NOT be skipped for CVE automation.
        MDEDevice("4", "test4", "Active", "Windows", "Onboarded", ["LRI", "SKIP-CVE-[*]"], datetime.now(UTC)),
        # Should be skipped for CVE automation.
        MDEDevice("5", "test5", "Active", "Windows", "Onboarded", ["NFP", "SKIP-CVE"], datetime.now(UTC)),
        # Should NOT be skipped (invalid tag format).
        MDEDevice("6", "test6", "Active", "Windows", "Onboarded", ["DAE", "SKIP-CVE-"], datetime.now(UTC)),
    ]


def test_skip_device_cve():
    """
    Test the MDEDevice.should_skip method for CVE automation. 
    """
    devices = get_devices()

    skipped_machines = list(
        filter(
            lambda device: MDEDevice.should_skip(device, "CVE"),
            devices,
        )
    )
    # Only the id matter since that is what makes devices equal.
    assert MDEDevice("1", "test1", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("2", "test2", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("3", "test3", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("4", "test4", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("5", "test5", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) in skipped_machines
    assert MDEDevice("6", "test6", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines

    skipped_machines_specific = list(
        filter(
            lambda device: MDEDevice.should_skip(
                device, "CVE", cve="CVE-2021-4104"
            ),
            devices,
        )
    )
    # Only the id matter since that is what makes devices equal.
    assert MDEDevice("1", "test1", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines_specific
    assert MDEDevice("2", "test2", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) in skipped_machines_specific
    assert MDEDevice("3", "test3", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines_specific
    assert MDEDevice("4", "test4", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines_specific
    assert MDEDevice("5", "test5", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) in skipped_machines_specific
    assert MDEDevice("6", "test6", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines_specific

def test_skip_device_ddc2():
    """
    Test the MDEDevice.should_skip method for DDC2 automation.
    """
    devices = get_devices()

    skipped_machines = list(
        filter(
            lambda device: MDEDevice.should_skip(device, "DDC2"),
            devices,
        )
    )
    # Only the id matter since that is what makes devices equal.
    assert MDEDevice("1", "test1", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) in skipped_machines
    assert MDEDevice("2", "test2", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("3", "test3", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("4", "test4", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("5", "test5", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("6", "test6", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines


def test_skip_device_ddc3():
    """
    Test the MDEDevice.should_skip method for DDC3 automation
    """
    devices = get_devices()

    skipped_machines = list(
        filter(
            lambda device: MDEDevice.should_skip(device, "DDC3"),
            devices,
        )
    )
    # Only the id matter since that is what makes devices equal.
    assert MDEDevice("1", "test1", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) in skipped_machines
    assert MDEDevice("2", "test2", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("3", "test3", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("4", "test4", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("5", "test5", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
    assert MDEDevice("6", "test6", "Active", "Windows", "Onboarded", [], datetime.now(UTC)) not in skipped_machines
