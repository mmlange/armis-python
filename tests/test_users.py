#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103,S311

import random

import pytest
from test_fixture import armis_object


@pytest.fixture
def users(armis_object):
    return armis_object.get_users()


def test_get_users(users):
    assert len(users) > 0


def test_get_individual_users(users, armis_object):
    userids = sorted(list(users.keys()))
    randomuserids = random.choices(userids, k=2)

    for userid in randomuserids:
        u = armis_object.get_user(userid)
        assert userid == u["id"]


def test_get_invalid_user(users, armis_object):
    userids = sorted(list(users.keys()))
    userid_invalid = random.randint(
        userids[-1] * 2,
        userids[-1] * 2222,
    )
    with pytest.raises(RuntimeError):
        u = armis_object.get_user(userid_invalid)


def test_edit_userid4(users, armis_object):
    x = armis_object.edit_user(4, name="Some Name Here")
    assert x["data"]["id"] == 4


def test_edit_userid4_no_fields(users, armis_object):
    with pytest.raises(ValueError):
        x = armis_object.edit_user(4)


def test_edit_unknown_user(users, armis_object):
    userids = sorted(list(users.keys()))
    userid_invalid = random.randint(
        userids[-1] * 2,
        userids[-1] * 2222,
    )
    with pytest.raises(RuntimeError):
        u = armis_object.edit_user(userid_invalid, name="BLAH")
