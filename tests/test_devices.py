#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311


import pytest
import tenacity
from test_fixture import armis_object


@pytest.fixture(scope="module")
def device_asq():
    return 'in:devices timeFrame:"10 Seconds"'


def test_get_devices_count(armis_object, device_asq):
    x = armis_object.get_devices_count(
        asq=device_asq,
    )
    assert x > 0


def test_get_devices_count_noasq(armis_object):
    with pytest.raises(ValueError):
        armis_object.get_devices_count()


def test_get_devices_count_weird(armis_object):
    with pytest.raises(tenacity.RetryError):
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
            fields_wanted=["id", "od", "ad"],
        )


def test_get_devices_none(armis_object):
    x = armis_object.get_devices(
        asq='in:devices timeFrame:"1 Seconds" category:"Manufacturing Equipment" accessSwitch:"noswitchmatchesthis"',
        fields_wanted=["id"],
    )
    assert len(x) == 0


def test_get_devices_blankasq(armis_object):
    with pytest.raises(ValueError):
        armis_object.get_devices()


def test_get_devices_weird(armis_object):
    with pytest.raises(tenacity.RetryError):
        armis_object.get_devices(asq="in:nothing")
