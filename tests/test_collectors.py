#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random

import pytest
from test_fixture import armis_object


@pytest.fixture()
def collectors(armis_object):
    return armis_object.get_collectors()


def test_get_collectors(armis_object, collectors):
    for _ in range(5):
        randomcollectorid = random.choice(list(collectors.keys()))
        randomcollector = armis_object.get_collector(randomcollectorid)
        assert randomcollectorid == randomcollector["collectorNumber"]
