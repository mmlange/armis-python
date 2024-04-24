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


def test_get_integration_dne(armis_object, integrations):
    integration_ids = sorted(list(integrations.keys()))

    # let's make up an integration_id that does not exist, i.e. not in
    # this set:
    # 0 >= valid integrations_ids >= max(list of integration_ids)

    integrationid_dne = random.randint(
        integration_ids[-1] * 2,
        integration_ids[-1] * 2222,
    )

    integration_dne = armis_object.get_integration(integrationid_dne)
    assert len(integration_dne) == 0
