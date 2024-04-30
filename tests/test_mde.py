from lib.mde import MDEDevice


def get_devices() -> list[MDEDevice]:
    return [
        # Should NOT be skipped for CVE automation.
        MDEDevice("1", tags=["DAE", "SKIP-DDC2", "SKIP-DDC3"]),
        # Should be skipped for CVE-SPECIFIC automation if correct CVE is given.
        MDEDevice("2", tags=["NNH", "SKIP-CVE-[CVE-2021-4104]"]),
        # Should be skipped for CVE-SPECIFIC automation if correct CVE is given.
        MDEDevice("3", tags=["NNH", "SKIP-CVE-[CVE-2021-6829]"]),
        # Should be skipped for CVE-SPECIFIC automation.
        MDEDevice("4", tags=["LRI", "SKIP-CVE-[*]"]),
        # Should be skipped for CVE automation.
        MDEDevice("5", tags=["NFP", "SKIP-CVE"]),
        # Should NOT be skipped (invalid tag format).
        MDEDevice("6", tags=["DAE", "SKIP-CVE-"]),
    ]


def test_skip_device_cve():
    devices = get_devices()

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(device, automation_names=["CVE"]),
            devices,
        )
    )
    assert MDEDevice("1") in not_skipped_machines
    assert MDEDevice("2") in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("4") in not_skipped_machines
    assert MDEDevice("5") not in not_skipped_machines
    assert MDEDevice("6") in not_skipped_machines

    not_skipped_machines_specific = list(
        filter(
            lambda device: not MDEDevice.should_skip(
                device, automation_names=["CVE-SPECIFIC"], cve="CVE-2021-4104"
            ),
            devices,
        )
    )
    assert MDEDevice("1") in not_skipped_machines_specific
    assert MDEDevice("2") not in not_skipped_machines_specific
    assert MDEDevice("3") in not_skipped_machines_specific
    assert MDEDevice("4") not in not_skipped_machines_specific
    assert MDEDevice("5") in not_skipped_machines_specific
    assert MDEDevice("6") in not_skipped_machines_specific


def test_skip_device_ddc2():
    devices = get_devices()

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(device, automation_names=["DDC2"]),
            devices,
        )
    )
    assert MDEDevice("1") not in not_skipped_machines
    assert MDEDevice("2") in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("4") in not_skipped_machines
    assert MDEDevice("5") in not_skipped_machines


def test_skip_device_ddc3():
    devices = get_devices()

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(device, automation_names=["DDC3"]),
            devices,
        )
    )
    assert MDEDevice("1") not in not_skipped_machines
    assert MDEDevice("2") in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("4") in not_skipped_machines
    assert MDEDevice("5") in not_skipped_machines
    assert MDEDevice("6") in not_skipped_machines


def test_skip_device_multiple():
    devices = get_devices()

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(
                device,
                automation_names=["DDC3", "CVE", "CVE-SPECIFIC"],
                cve="CVE-2021-4104",
            ),
            devices,
        )
    )
    assert MDEDevice("1") not in not_skipped_machines
    assert MDEDevice("2") not in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("4") not in not_skipped_machines
    assert MDEDevice("5") not in not_skipped_machines
    assert MDEDevice("6") in not_skipped_machines
