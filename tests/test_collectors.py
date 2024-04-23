#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random
import sys

import pytest
from test_fixture import armis_object


def test_get_collector_count(armis_object):
    c = armis_object.get_collectors_count()
    assert c > 0


def test_get_collectors(armis_object):
    collectors = armis_object.get_collectors()
    randomcollectorid = random.choice(list(collectors.keys()))

    randomcollector = armis_object.get_collector(randomcollectorid)
    assert randomcollectorid == randomcollector["collectorNumber"]
