from lib.mde import MDEDevice


def get_devices() -> list[MDEDevice]:
    return [
        # Should NOT be skipped for CVE automation.
        MDEDevice("1", tags=["DAE", "SKIP-DDC2", "SKIP-DDC3"]),
        # Should be skipped for CVE automation if correct CVE is given.
        MDEDevice("2", tags=["NNH", "SKIP-CVE-[CVE-2021-4104]"]),
        # Should be skipped for CVE automation if correct CVE is given.
        MDEDevice("3", tags=["NNH", "SKIP-CVE-[CVE-2021-6829]"]),
        # Should NOT be skipped for CVE automation.
        MDEDevice("4", tags=["LRI", "SKIP-CVE-[*]"]),
        # Should be skipped for CVE automation.
        MDEDevice("5", tags=["NFP", "SKIP-CVE"]),
        # Should NOT be skipped (invalid tag format).
        MDEDevice("6", tags=["DAE", "SKIP-CVE-"]),
    ]


def test_skip_device_cve():
    devices = get_devices()

    skipped_machines = list(
        filter(
            lambda device: MDEDevice.should_skip(device, "CVE"),
            devices,
        )
    )
    assert MDEDevice("1") not in skipped_machines
    assert MDEDevice("2") not in skipped_machines
    assert MDEDevice("3") not in skipped_machines
    assert MDEDevice("3") not in skipped_machines
    assert MDEDevice("4") not in skipped_machines
    assert MDEDevice("5") in skipped_machines
    assert MDEDevice("6") not in skipped_machines

    skipped_machines_specific = list(
        filter(
            lambda device: MDEDevice.should_skip(
                device, "CVE", cve="CVE-2021-4104"
            ),
            devices,
        )
    )
    assert MDEDevice("1") not in skipped_machines_specific
    assert MDEDevice("2") in skipped_machines_specific
    assert MDEDevice("3") not in skipped_machines_specific
    assert MDEDevice("4") not in skipped_machines_specific
    assert MDEDevice("5") in skipped_machines_specific
    assert MDEDevice("6") not in skipped_machines_specific


def test_skip_device_ddc2():
    devices = get_devices()

    skipped_machines = list(
        filter(
            lambda device: MDEDevice.should_skip(device, "DDC2"),
            devices,
        )
    )
    assert MDEDevice("1") in skipped_machines
    assert MDEDevice("2") not in skipped_machines
    assert MDEDevice("3") not in skipped_machines
    assert MDEDevice("4") not in skipped_machines
    assert MDEDevice("5") not in skipped_machines
    assert MDEDevice("6") not in skipped_machines


def test_skip_device_ddc3():
    devices = get_devices()

    skipped_machines = list(
        filter(
            lambda device: MDEDevice.should_skip(device, "DDC3"),
            devices,
        )
    )
    assert MDEDevice("1") in skipped_machines
    assert MDEDevice("2") not in skipped_machines
    assert MDEDevice("3") not in skipped_machines
    assert MDEDevice("4") not in skipped_machines
    assert MDEDevice("5") not in skipped_machines
    assert MDEDevice("6") not in skipped_machines

