#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random

import pytest
from test_fixture import armis_object


@pytest.fixture
def sitelist(armis_object):
    return armis_object.get_sites()


def test_sitelist(sitelist):
    assert len(sitelist) > 0


def test_get_site(sitelist):
    siteids = list(sitelist.keys())
    siteid = random.choice(siteids)
    assert siteid == sitelist[siteid]["id"]
