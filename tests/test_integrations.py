#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311
import random

import pytest
import tenacity
from test_fixture import armis_object


def test_get_integrations_count(armis_object):
    x = armis_object.get_integrations_count()
    assert x > 0


@pytest.fixture(scope="module")
def integrations(armis_object):
    return armis_object.get_integrations()


def test_get_integration(integrations, armis_object):
    for _ in range(5):
        randomintegrationid = random.choice(list(integrations.keys()))
        randomintegration = armis_object.get_integration(randomintegrationid)
        assert randomintegrationid == randomintegration["id"]


def test_get_integration_invalid(armis_object, integrations):
    integration_ids = sorted(list(integrations.keys()))

    # let's make up an integration_id that does not exist, i.e. not in
    # this set:
    # 0 >= valid integrations_ids >= max(list of integration_ids)

    integrationid_invalid = random.randint(
        integration_ids[-1] * 2,
        integration_ids[-1] * 2222,
    )

    integration_invalid = armis_object.get_integration(integrationid_invalid)
    assert len(integration_invalid) == 0


@pytest.fixture
def integration(armis_object):
    random_number = random.randint(0, 939393339)
    random_name = f"Test Integration #{random_number}"
    x = armis_object.create_integration(
        collector_id=9157,
        integration_name=random_name,
        integration_type="SWITCH",
        integration_params={"sniff_interface": "eno5"},
    )
    return x


def test_create_integration(integration):
    integration_id = integration["data"]["id"]
    print("integration_id=", integration_id)

    assert integration_id > 0


def test_delete_integration(integration, armis_object):
    integration_id = integration["data"]["id"]

    print("deleting integration_id=", integration_id)
    x = armis_object.delete_integration(integration_id)
    print("x=", x)
    assert x["success"] is True
