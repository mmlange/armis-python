#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import pytest
from test_fixture import armis_object


def test_get_search_count(armis_object):
    x = armis_object.get_search_count(
        asq='in:activity timeFrame:"1 Hours"',
    )
    print("x=", x)
    assert x >= 0


def test_get_search(armis_object):
    x = armis_object.get_search(
        asq='in:activity timeFrame:"1 Hours"',
        fields_wanted=["activityUUID"],
    )
    # print("x=", x)
    assert len(x) >= 0


def test_get_search_count_bad_asq(armis_object):
    with pytest.raises(RuntimeError):
        x = armis_object.get_search_count(
            asq='in:activitYBADDD timeFrame:"7 Days"',
        )
        print("x=", x)


def test_get_search_count_noasq(armis_object):
    with pytest.raises(TypeError):
        armis_object.get_search_count()


def test_get_search_count_weird(armis_object):
    with pytest.raises(RuntimeError):
        armis_object.get_search_count(asq="in:nothing")


def test_get_search_none(armis_object):
    x = armis_object.get_search(
        asq='in:devices timeFrame:"1 Seconds" category:"Manufacturing Equipment" accessSwitch:"noswitchmatchesthis"',
        fields_wanted=["id"],
    )
    assert len(x) == 0


def test_get_search_blankasq(armis_object):
    with pytest.raises(TypeError):
        armis_object.get_search()
