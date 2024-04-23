#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random

import pytest
from test_fixture import armis_object

boundarylist = (1, 2, 10, 77)


def test_boundarycount(armis_object):
    bc = armis_object.get_boundaries_count()
    assert bc > 0


def test_get_boundary_by_id(armis_object):
    for boundary_id in boundarylist:
        x = armis_object.get_boundary(boundary_id=boundary_id)
        assert len(x) > 0


def test_get_boundary_by_id_blank(armis_object):
    with pytest.raises(ValueError):
        armis_object.get_boundary()


def test_get_boundaries(armis_object):
    x = armis_object.get_boundaries()
    assert len(x.keys()) > 0
