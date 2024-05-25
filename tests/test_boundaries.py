#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random

import pytest
from test_fixture import armis_object


@pytest.fixture
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


def test_get_boundary_by_id_none(armis_object):
    with pytest.raises(ValueError):
        armis_object.get_boundary(None)


def test_create_and_delete_boundary(armis_object):
    boundary_ids = []
    for _ in range(2):
        boundary_name = "test boundary #" + str(random.randint(1, 232342))
        ruleaql = {
            "or": [
                "name:fasfd;salkdfjasflskaj",
            ],
        }
        x = armis_object.create_boundary(
            name=boundary_name,
            ruleaql=ruleaql,
            affected_sites="Test",
        )
        boundary_ids.append(x["data"]["id"])
        assert x["success"]

    for boundary_id in boundary_ids:
        print("boundary_id=", boundary_id)
        x = armis_object.delete_boundary(boundary_id=boundary_id)
        print("delete boundary result=", x)


def test_create_boundary_with_no_params(armis_object):
    with pytest.raises(ValueError):
        x = armis_object.create_boundary()


def test_create_boundary_with_no_name(armis_object):
    with pytest.raises(ValueError):
        x = armis_object.create_boundary(
            ruleaql={
                "or": [
                    "name:fasfd;salkdfjasflskaj",
                ],
            },
        )


def test_create_boundary_with_no_ruleaql(armis_object):
    with pytest.raises(ValueError):
        x = armis_object.create_boundary(
            name="does-not-matter",
        )
