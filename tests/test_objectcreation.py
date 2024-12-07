#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103
import pathlib as pl

import pytest
from dotenv import dotenv_values

from armis import ArmisCloud


@pytest.fixture(scope="module")
def config():
    envfile = pl.Path.home() / ".env"
    config = dotenv_values(envfile)
    if "TEST_ARMIS_TENANT_HOSTNAME" not in config:
        pytest.skip("missing TEST_ARMIS_TENANT_HOSTNAME from env file")

    if "TEST_ARMIS_API_SECRET_KEY" not in config:
        pytest.skip("missing TEST_ARMIS_API_SECRET_KEY from env file")

    return config


def test_object_creation_missing_tenant_hostname(config):
    with pytest.raises(ValueError):
        ArmisCloud(
            api_secret_key=config["TEST_ARMIS_API_SECRET_KEY"],
            log_level="DEBUG",
            api_page_size=5_000,
        )


def test_object_creation_missing_secret_key(config):
    with pytest.raises(ValueError):
        ArmisCloud(
            tenant_hostname=config["TEST_ARMIS_TENANT_HOSTNAME"],
            log_level="DEBUG",
            api_page_size=5_000,
        )


def test_object_creation_large_page_size(config):
    with pytest.warns(UserWarning):
        ArmisCloud(
            api_secret_key=config["TEST_ARMIS_API_SECRET_KEY"],
            tenant_hostname=config["TEST_ARMIS_TENANT_HOSTNAME"],
            log_level="DEBUG",
            api_page_size=5_000_000,
        )


def test_object_creation_incorrect_loglevel(config):
    with pytest.raises(ValueError):
        ArmisCloud(
            api_secret_key=config["TEST_ARMIS_API_SECRET_KEY"],
            tenant_hostname=config["TEST_ARMIS_TENANT_HOSTNAME"],
            log_level="BADLOGLEVEL",
        )
