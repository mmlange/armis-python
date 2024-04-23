#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103

import pytest
from test_fixture import armis_object


def test_api_request_post_data_json(armis_object):
    with pytest.raises(ValueError):
        armis_object._api_http_request(
            method="POST",
            url="https://www.httpbin.org/post",
            content="somedata",
            json={"id": "unknown"},
        )


def test_api_request_post_missing_url(armis_object):
    with pytest.raises(ValueError):
        armis_object._api_http_request(
            method="POST",
            content="somedata",
        )


def test_api_request_missing_method(armis_object):
    with pytest.raises(ValueError):
        armis_object._api_http_request(
            url="doesn't matter",
            content="somedata",
        )


def test_api_request_unsupported_method(armis_object):
    with pytest.raises(ValueError):
        armis_object._api_http_request(
            url="doesn't matter",
            method="BLAHBLAH",
            content="somedata",
        )


def test_api_request_delete_content(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/delete",
        method="DELETE",
        content="somedata",
    )
    assert len(data.text) > 0


def test_api_request_delete_json(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/delete",
        method="DELETE",
        json={"id": "unknown"},
    )
    assert len(data.text) > 0


def test_api_request_delete_nocontent(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/delete",
        method="DELETE",
    )
    assert len(data.text) > 0


def test_api_request_get(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/json",
        method="GET",
    )
    assert len(data.text) > 0


def test_api_request_patch_json(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/patch",
        method="PATCH",
        json={"patchme": "yes"},
    )
    assert len(data.text) > 0


def test_api_request_patch_content(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/patch",
        method="PATCH",
        content="somedata",
    )
    assert len(data.text) > 0


def test_api_request_post_json(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/post",
        method="POST",
        json={"hello": "there"},
    )
    assert len(data.text) > 0


def test_api_request_post_content(armis_object):
    data = armis_object._api_http_request(
        url="https://www.httpbin.org/post",
        method="POST",
        content="some data",
    )
    assert len(data.text) > 0


def test_api_request_post_nothing(armis_object):
    with pytest.raises(ValueError):
        armis_object._api_http_request(
            url="https://www.httpbin.org/post",
            method="POST",
        )
