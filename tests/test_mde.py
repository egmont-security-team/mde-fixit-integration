from lib.mde import MDEDevice


def test_skip_device_cve():
    devices = [
        # Should NOT be skipped for CVE automation.
        MDEDevice("1", tags=["DAE", "SKIP-DDC2", "SKIP-DDC3"]),
        # Should be skipped for CVE-SPECFIC automation if correct CVE is given.
        MDEDevice("2", tags=["NNH", "SKIP-CVE-[CVE-2021-4104]"]),
        # Should be skipped for CVE-SPECFIC automation if correct CVE is given.
        MDEDevice("3", tags=["NNH", "SKIP-CVE-[CVE-2021-6829]"]),
        # Should be skipped for CVE-SPECFIC automation.
        MDEDevice("4", tags=["LRI", "SKIP-CVE-[*]"]),
        # Should be skipped for CVE automation.
        MDEDevice("5", tags=["NFP", "SKIP-CVE"]),
        # Should NOT be skipped (invalid tag format).
        MDEDevice("6", tags=["DAE", "SKIP-CVE-"]),
    ]

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(device, automations=["CVE"]),
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

    not_skipped_machines_specefic = list(
        filter(
            lambda device: not MDEDevice.should_skip(
                device, automations=["CVE-SPECEFIC"], cve="CVE-2021-4104"
            ),
            devices,
        )
    )
    assert MDEDevice("1") in not_skipped_machines_specefic
    assert MDEDevice("2") not in not_skipped_machines_specefic
    assert MDEDevice("3") in not_skipped_machines_specefic
    assert MDEDevice("4") not in not_skipped_machines_specefic
    assert MDEDevice("5") in not_skipped_machines_specefic
    assert MDEDevice("6") in not_skipped_machines_specefic


def test_skip_device_ddc2():
    devices = [
        # Should NOT be skipped for CVE automation.
        MDEDevice("1", tags=["DAE", "SKIP-DDC2", "SKIP-DDC3"]),
        # Should be skipped for CVE-SPECFIC automation.
        MDEDevice("2", tags=["NNH", "SKIP-CVE-[CVE-2021-4104]"]),
        # Should be skipped for CVE-SPECFIC automation.
        MDEDevice("3", tags=["LRI", "SKIP-CVE-[*]"]),
        # Should be skipped for CVE automation.
        MDEDevice("4", tags=["NFP", "SKIP-CVE"]),
        # Should NOT be skipped (invalid tag format).
        MDEDevice("5", tags=["DAE", "SKIP-CVE-"]),
    ]

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(device, automations=["DDC2"]),
            devices,
        )
    )
    assert MDEDevice("1") not in not_skipped_machines
    assert MDEDevice("2") in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("4") in not_skipped_machines
    assert MDEDevice("5") in not_skipped_machines


def test_skip_device_ddc3():
    devices = [
        # Should NOT be skipped for CVE automation.
        MDEDevice("1", tags=["DAE", "SKIP-DDC2", "SKIP-DDC3"]),
        # Should be skipped for CVE-SPECFIC automation.
        MDEDevice("2", tags=["NNH", "SKIP-CVE-[CVE-2021-4104]"]),
        # Should be skipped for CVE-SPECFIC automation.
        MDEDevice("3", tags=["LRI", "SKIP-CVE-[*]"]),
        # Should be skipped for CVE automation.
        MDEDevice("4", tags=["NFP", "SKIP-CVE"]),
        # Should NOT be skipped (invalid tag format).
        MDEDevice("5", tags=["DAE", "SKIP-CVE-"]),
    ]

    not_skipped_machines = list(
        filter(
            lambda device: not MDEDevice.should_skip(device, automations=["DDC3"]),
            devices,
        )
    )
    assert MDEDevice("1") not in not_skipped_machines
    assert MDEDevice("2") in not_skipped_machines
    assert MDEDevice("3") in not_skipped_machines
    assert MDEDevice("4") in not_skipped_machines
    assert MDEDevice("5") in not_skipped_machines
