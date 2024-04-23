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
def test_get_integrations(armis_object):
    return armis_object.get_integrations()


def test_get_integration(test_get_integrations, armis_object):
    randomintegrationid = random.choice(list(test_get_integrations.keys()))
    randomintegration = armis_object.get_integration(randomintegrationid)
    assert randomintegrationid == randomintegration["id"]


def test_get_integration_dne(armis_object):
    integration_dne = armis_object.get_integration(99423432)
    assert len(integration_dne) == 0
