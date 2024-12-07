#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311


import pytest
import tenacity
from test_fixture import armis_object


@pytest.fixture(scope="module")
def device_asq():
    return 'in:devices timeFrame:"10 Minutes"'


def test_get_devices_count(armis_object, device_asq):
    x = armis_object.get_devices_count(
        asq=device_asq,
    )
    assert x >= 0


def test_get_devices_count_noasq(armis_object):
    with pytest.raises(TypeError):
        armis_object.get_devices_count()


def test_get_devices_count_weird(armis_object):
    with pytest.raises(RuntimeError):
        armis_object.get_devices_count(asq="in:nothing")


def test_get_devices(armis_object, device_asq):
    x = armis_object.get_devices(
        asq=device_asq,
    )
    assert len(x) > 0


def test_get_devices_mismatched_fields(armis_object, device_asq):
    with pytest.raises(ValueError):
        armis_object.get_devices(
            asq=device_asq,
            fields_wanted=["id", "not", "valid", "fields"],
        )


def test_get_devices_ensure_fields_match(armis_object, device_asq):
    fields_wanted = [
        "id",
        "boundaries",
        "name",
        "accessSwitch",
        "boundaries",
        "category",
        "operatingSystem",
        "operatingSystemVersion",
        "osBuildNumber",
        "publicIp",
        "purdueLevel",
    ]
    x = armis_object.get_devices(
        asq=device_asq,
        fields_wanted=fields_wanted,
    )

    firstdevice = x[0]
    fields_retrieved = list(firstdevice.keys())
    fields_difference = set(fields_wanted) - set(fields_retrieved)
    assert len(fields_difference) == 0


def test_get_devices_none(armis_object):
    x = armis_object.get_devices(
        asq='in:devices timeFrame:"1 Seconds" category:"Manufacturing Equipment" accessSwitch:"noswitchmatchesthis"',
        fields_wanted=["id"],
    )
    assert len(x) == 0


def test_get_devices_blankasq(armis_object):
    with pytest.raises(TypeError):
        armis_object.get_devices()


def test_get_devices_weird(armis_object):
    with pytest.raises(RuntimeError):
        armis_object.get_devices(asq="in:nothing")
