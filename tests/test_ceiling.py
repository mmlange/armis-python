#!/usr/bin/python3
# ruff: noqa: SLF001 PLR2004,F811,D103

import pytest
from test_fixture import armis_object


def test_ceilingup(armis_object):
    assert armis_object._ceiling_up(1504654654, 1000) == 1504655000
    assert armis_object._ceiling_up(43223, 100) == 43300
    assert armis_object._ceiling_up(123456, 10) == 123460

    assert armis_object._ceiling_up(123456, 1000) != 12
    assert armis_object._ceiling_up(123456, 1000) != 123460

    with pytest.raises(ValueError):
        armis_object._ceiling_up(
            "string here",
            1000,
        )


def test_ceilingup_no_nearest(armis_object):
    with pytest.raises(ValueError):
        armis_object._ceiling_up(
            123456,
            None,
        )

    with pytest.raises(TypeError):
        armis_object._ceiling_up(
            123456,
        )
