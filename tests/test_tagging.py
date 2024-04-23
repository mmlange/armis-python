#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103
import random

import pytest
import tenacity
from test_fixture import armis_object


def test_tag_no_device_id(armis_object):
    with pytest.raises(ValueError):
        armis_object.tag_device(
            tags="testtag",
            action="add",
        )


def test_tag_device_id_no_action(armis_object):
    with pytest.raises(Exception):
        armis_object.tag_device(
            device_id=0,
            tags="testtag",
        )


def test_tag_device_id_weird_action(armis_object):
    with pytest.raises(Exception):
        armis_object.tag_device(
            device_id=0,
            tags="testtag",
            action="failme",
        )


def test_tag_device_id_no_tags(armis_object):
    with pytest.raises(Exception):
        armis_object.tag_device(
            device_id=0,
            action="remove",
        )


def test_tag_device_id_str_add(armis_object):
    with pytest.raises(Exception):
        armis_object.tag_device(
            device_id=0,
            tags="testtag",
            action="add",
        )


def test_tag_device_id_str_remove(armis_object):
    with pytest.raises(Exception):
        armis_object.tag_device(
            device_id=0,
            tags="testtag",
            action="remove",
        )
