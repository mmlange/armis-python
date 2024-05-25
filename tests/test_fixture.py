#!/usr/bin/python3
# ruff: noqa: F811,SLF001,D103
import pathlib as pl

import pytest
from dotenv import dotenv_values

from armis import ArmisCloud

envfile = pl.Path.home() / ".env"
config = dotenv_values(envfile)


@pytest.fixture(scope="module")
def armis_object():
    if "TEST_ARMIS_TENANT_HOSTNAME" not in config:
        pytest.skip("missing TEST_ARMIS_TENANT_HOSTNAME from env file")

    if "TEST_ARMIS_API_SECRET_KEY" not in config:
        pytest.skip("missing TEST_ARMIS_API_SECRET_KEY from env file")

    return ArmisCloud(
        api_secret_key=config["TEST_ARMIS_API_SECRET_KEY"],
        tenant_hostname=config["TEST_ARMIS_TENANT_HOSTNAME"],
        log_level="DEBUG",
        api_page_size=5_000,
    )
