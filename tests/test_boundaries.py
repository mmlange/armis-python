#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random

import pytest
from test_fixture import armis_object


@pytest.fixture()
def boundaries(armis_object):
    return armis_object.get_boundaries()


def test_get_boundaries(boundaries):
    assert len(list(boundaries.keys())) > 0


def test_get_boundary_by_id(boundaries, armis_object):
    boundaryids = list(boundaries.keys())

    for _ in range(5):
        boundaryid = random.choice(boundaryids)
        assert boundaryid == armis_object.get_boundary(boundary_id=boundaryid)["id"]


def test_get_boundary_by_id_blank(armis_object):
    with pytest.raises(TypeError):
        armis_object.get_boundary()
