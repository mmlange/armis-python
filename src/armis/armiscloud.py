#!/usr/bin/python3

# SPDX-FileCopyrightText: 2024-present Matthew Lange <mmlange@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import contextlib
import gzip
import math
import pathlib as pl
import sys
import tempfile
import warnings

import httpx
import msgspec
import pendulum
from loguru import logger
from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from .__about__ import __version__


class ArmisCloud:
    """Armis class for interfacing with the Armis cloud."""

    # NOTE: Per Armis' API Guide 1.8 (dated 5/30/2023), the Armis
    # API has a maximum page size of 5,000.
    ARMIS_MAXIMUM_API_PAGE_SIZE: int = 5_000

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """Construct an Armis class.

        Parameters
        ----------
        api_secret_key : str
            The secret key to use when talking to the Armis cloud.
        api_page_size : int, optional
            Page size to use when talking to the Armis cloud.
        tenant_hostname : str
            The hostname of the Armis cloud tenant, e.g. customer.armis.com
        log_level : {'INFO', 'CRITICAL', 'ERROR', 'WARNING', 'DEBUG', 'NOTSET'}, default='INFO'
            Log level to log at, e.g. CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET.
        temporary_directory : str, optional
            Location of temporary directory, or if blank, one will be
            automatically assigned.

        Examples
        --------
        ::

            armis = ArmisCloud(
                api_secret_key="secretkeyhere",
                tenant_hostname="customer1.armis.com",
            )

        Returns
        -------
        Armis
            Armis object.

        Notes
        -----
        If you provide your own `temporary_directory`, you will need to empty this
        directory yourself.

        """
        self.logger = logger
        self.logger.remove()
        log_level = kwargs.get("log_level", "INFO")
        self.logger.add(sys.stdout, level=log_level)
        self.logger.info(f"wanted_log_level={log_level}")
        self.logger.disable("armis.armiscloud")

        self._authorization_token = 0
        self._authorization_token_expiration = 0

        self.temporary_directory = kwargs.get("temporary_directory")
        if self.temporary_directory is None:
            self.temporary_directory = tempfile.TemporaryDirectory()

        self.logger.info(f"temporary_directory={self.temporary_directory.name}")

        self._http_timeout: int = 100

        self.ARMIS_API_PAGE_SIZE: int = kwargs.get(
            "api_page_size",
            self.ARMIS_MAXIMUM_API_PAGE_SIZE,
        )
        if self.ARMIS_API_PAGE_SIZE > self.ARMIS_MAXIMUM_API_PAGE_SIZE:
            self.logger.info(
                f"page size requested={self.ARMIS_API_PAGE_SIZE}, "
                f"page size maximum is={self.ARMIS_MAXIMUM_API_PAGE_SIZE}",
            )
            warnings.warn(
                "page size requested="
                + str(self.ARMIS_API_PAGE_SIZE)
                + ", page size maximum="
                + str(self.ARMIS_MAXIMUM_API_PAGE_SIZE),
                stacklevel=2,
            )
        self.logger.debug(f"api_page_size={self.ARMIS_API_PAGE_SIZE}")
        self.API_SECRET_KEY: str = kwargs.get("api_secret_key")
        if self.API_SECRET_KEY is None:
            raise ValueError("No secret key provided")

        self.HTTP_RETRY_MAX: int = 5
        self._httpx_limits = httpx.Limits(
            max_keepalive_connections=50,
            max_connections=200,
            keepalive_expiry=120,
        )
        self.httpx_client = self._get_httpx_client()

        tenant_hostname = kwargs.get("tenant_hostname")
        if tenant_hostname is None:
            raise ValueError("tenant_hostname is required")

        self.TENANT_BASE_URL = f"https://{tenant_hostname}/api/"
        self.logger.debug(f"TENANT_BASE_URL={self.TENANT_BASE_URL}")

        # Note that if you're making multiple calls to decode, it's more efficient
        # to create a Decoder once and use the Decoder.decode method instead.
        self._json_decoder = msgspec.json.Decoder()
        self._json_encoder = msgspec.json.Encoder()

    # cleanup
    def __del__(self):
        # close all outstanding httpx connections
        with contextlib.suppress(Exception):
            self.httpx_client.close()

    @staticmethod
    def _ceiling_up(number, nearest: int):
        if not isinstance(number, (int, float)):
            raise ValueError("number " + str(number) + " is not an int or float")
        if nearest is None:
            raise ValueError("nearest was not provided")

        return math.ceil(number / nearest) * nearest

    def _get_httpx_client(self):
        with contextlib.suppress(AttributeError):
            self.httpx_client.close()

        return httpx.Client(
            event_hooks={
                "response": [self._httpx_callback_request_raise_4xx_5xx],
            },
            follow_redirects=True,
            headers={
                "user-agent": f"Armis Python Library {__version__}",
            },
            http2=True,
            limits=self._httpx_limits,
            timeout=self._http_timeout,
            trust_env=False,
        )

    def _httpx_callback_request_raise_4xx_5xx(self, response):
        self.logger.debug(f"_httpx_callback_request_raise_4xx_5xx raising alert, status_code={response.status_code}")

        if response.status_code == httpx.codes.UNAUTHORIZED:
            self.logger.debug("401 unauthorized, our token probably expired")
            self.authorization_token_expiration = 0
            response.raise_for_status()

    def _api_http_request(self, **kwargs):
        """Wrap the request function and handles the authorization token.

        Parameters
        ----------
        method : str
            HTTP method, one of DELETE, GET, PATCH, POST, PUT, etc.
        url : str
            the URL endpoint
        content : str, optional
            content to pass along
        headers : dict, optional
            headers to pass along
        json : dict, optional
            json to pass along
        params : dict, optional
            params to pass along
        maximum_retries : int, optional
            maximum number of times to retry connection

        Raises
        ------
        ValueError
            If data provided is invalid.

        Returns
        -------
        response : request.response object
        """
        self.logger.debug(f"kwargs={kwargs}")

        method: str = kwargs.get("method")
        url = kwargs.get("url")
        content: str = kwargs.get("content", "")
        headers: dict = kwargs.get("headers", {})
        json: dict = kwargs.get("json", {})
        params: dict = kwargs.get("params", {})
        maximum_retries: int = kwargs.get("maximum_retries", self.HTTP_RETRY_MAX)

        if len(content) > 0 and len(json) > 0:
            raise ValueError("You can send content or JSON, not both")

        if method is None or url is None:
            raise ValueError("no method or url")

        method = method.upper()

        if method not in {
            "DELETE",
            "GET",
            "PATCH",
            "POST",
        }:
            raise ValueError("method must be one of DELETE, GET, PATCH, or POST")

        for attempt in Retrying(  # noqa: RET503
            retry=retry_if_exception_type(httpx.HTTPStatusError)
            | retry_if_exception_type(msgspec.DecodeError)
            | retry_if_exception_type(httpx.RemoteProtocolError)
            | retry_if_exception_type(httpx.ConnectError)
            | retry_if_exception_type(httpx.ReadTimeout),
            wait=wait_random_exponential(multiplier=1, max=10),
            stop=stop_after_attempt(maximum_retries),
        ):
            with attempt:
                self.logger.info(f"ATTEMPT NUMBER {attempt.retry_state.attempt_number} of {maximum_retries}")
                if attempt.retry_state.attempt_number > 1 and "length" in params:
                    self.logger.info(f'attempt number >1, reducing page size, was {params["length"]}')
                    params["length"] = int(params["length"] * 0.75)
                    self.logger.info(f'reducing page size, now {params["length"]}')

                self._update_authorization_token()

                if method == "GET":
                    self.logger.debug(f"GETting URL={url}")
                    r = self.httpx_client.get(
                        str(url),
                        headers=headers,
                        params=params,
                    )
                    self.logger.debug(f"r.status_code={r.status_code}")
                if method == "POST":
                    if len(content) == 0 and len(json) == 0:
                        raise ValueError("You must send either content or JSON")
                    self.logger.debug(f"POSTing URL={url}")
                    if len(json) > 0:
                        r = self.httpx_client.post(
                            str(url),
                            json=json,
                            headers=headers,
                            params=params,
                        )
                    elif len(content) > 0:
                        r = self.httpx_client.post(
                            str(url),
                            content=content,
                            headers=headers,
                            params=params,
                        )

                    self.logger.debug(f"r.status_code={r.status_code}")

                if method == "PATCH":
                    self.logger.debug(f"PATCHing URL={url}")
                    if len(json) > 0:
                        r = self.httpx_client.patch(
                            str(url),
                            json=json,
                            headers=headers,
                            params=params,
                        )
                    elif len(content) > 0:
                        r = self.httpx_client.patch(
                            str(url),
                            content=content,
                            headers=headers,
                            params=params,
                        )

                    self.logger.debug(f"r.status_code={r.status_code}")

                if method == "DELETE":
                    # NOTE: httpx_client.delete method doesn't work as you're
                    # not supposed to send data with a DELETE request.
                    # Instead, we'll use the generic request method to do this.
                    # See
                    # https://tinyurl.com/httpx-delete
                    self.logger.debug(f"DELETEing URL={url}")
                    if len(json) > 0:
                        r = self.httpx_client.request(
                            "DELETE",
                            str(url),
                            json=json,
                            headers=headers,
                            params=params,
                        )
                    elif len(content) > 0:
                        r = self.httpx_client.request(
                            "DELETE",
                            str(url),
                            content=content,
                            headers=headers,
                            params=params,
                        )
                    else:
                        r = self.httpx_client.request(
                            "DELETE",
                            str(url),
                            headers=headers,
                            params=params,
                        )
                        # this usually returns a 204, so no text will be present
                        # just return the result
                        return r  # noqa: RET504

                self.logger.debug(f"response http version={r.http_version}")

                try:
                    _ = self._json_decoder.decode(r.text)
                except msgspec.DecodeError as err:
                    self.logger.critical(f"exception: {err}")
                    self.logger.debug(f"text of response={r.text}")
                    raise err

                self.logger.debug(f"size of return text={len(r.text)}")
                self.logger.debug(f"return text[1000]={r.text[:1000]}")

                return r

    def _update_authorization_token(self) -> None:
        """Fetch an authorization token.

        Check if the token we have is still valid.  If not, get a new token and
        stash it in the object and update the HTTPX client header.
        """
        self.logger.debug("BEGIN")
        now = pendulum.now().timestamp()
        remaining_time = self._authorization_token_expiration - now
        self.logger.debug(f"now={now}")
        self.logger.debug(f"remaining_time={remaining_time}")

        if remaining_time < 1_000:  # noqa: PLR2004
            self.logger.debug("remaining_time <1000")
            self.logger.debug(f"expires={self._authorization_token_expiration}")
            self.logger.debug("now > _authorization_token_expiration")
            self.logger.debug("_authorization_token expired, getting new one")
            url = self.TENANT_BASE_URL + "v1/access_token/"
            r = self.httpx_client.post(
                str(url),
                data={
                    "secret_key": self.API_SECRET_KEY,
                },
            )
            returnjson = self._json_decoder.decode(r.text)
            self.logger.debug(f"return text={r.text}")

            if "access_token" in returnjson["data"]:
                self._authorization_token = returnjson["data"]["access_token"]
                self.logger.debug(f'RAW expiration_utc={returnjson["data"]["expiration_utc"]}')
                self._authorization_token_expiration = pendulum.parse(
                    returnjson["data"]["expiration_utc"],
                ).timestamp()
                self.logger.debug(f"RAW authorization_token={self._authorization_token}")
                self.logger.debug(f"parsed authorization_token_expiration={self._authorization_token_expiration}")
            else:
                self.logger.debug("access_token=None")  # pragma: no cover
        else:
            self.logger.debug(f"expires={self._authorization_token_expiration}")
            self.logger.debug("now < _authorization_token_expiration")

        self.httpx_client.headers["Authorization"] = self._authorization_token

        self.logger.debug("END")

    def create_boundary(self, **kwargs) -> dict:
        """Update a boundary given a boundary_id, name, and ruleaql.

        Parameters
        ----------
        name : str
            new name of the boundary
        affected_sites : str|list, optional
            sites affected
        ruleaql : dict
            aql to define the boundary

        Returns
        -------
        creation_results : dict

        Notes
        -----
        The cloud must be running at version >=R-23.3-S182.
        """
        self.logger.debug(f"kwargs={kwargs}")

        affected_sites = kwargs.get("affected_sites")
        name = kwargs.get("name")
        ruleaql = kwargs.get("ruleaql")

        if name is None and ruleaql is None:
            raise ValueError("name and ruleaql are required")
        if name is None:
            raise ValueError("name is required")
        if ruleaql is None:
            raise ValueError("ruleaql is required")

        boundary_payload = {
            "name": name,
            "ruleAql": ruleaql,
        }

        if affected_sites is not None:
            if isinstance(affected_sites, list):
                self.logger.debug(
                    "affected_types was list, converting to a comma-delimited str",
                )
                # check if there is a comma in the name
                # we can't update a boundary using an affected site with a comma in it
                for affected_site in affected_sites:
                    if "," in affected_site:
                        raise ValueError(
                            "Site '" + affected_site + "' contains a comma - Armis API doesn't support this",
                        )

                affected_sites = ",".join(affected_sites)

            boundary_payload["affectedSites"] = affected_sites

        self.logger.debug(f"payload is now {boundary_payload}")

        # create the boundary
        url = self.TENANT_BASE_URL + "v1/boundaries/"
        self.logger.debug(f"url={url}")
        boundary_create = self._api_http_request(
            method="POST",
            url=url,
            json=boundary_payload,
        )
        self.logger.debug(f"return text={boundary_create.text}")
        self.logger.debug(f"status_code={boundary_create.status_code}")

        # when creating a boundary, you get 201 back if it was created
        if boundary_create.status_code != httpx.codes.CREATED:
            self.logger.info(f"FAILED boundary create for name={name}")
            self.logger.debug(boundary_create.text)
            raise RuntimeError("boundary update issue", boundary_create.text)

        return self._json_decoder.decode(boundary_create.text)

    def delete_boundary(self, boundary_id: int) -> dict:
        """Delete a boundary given a boundary_id.

        Parameters
        ----------
        boundary_id : int
            The ID of the boundary tool to retrieve.

        Returns
        -------
        delete_results : dict
        """
        url = self.TENANT_BASE_URL + f"v1/boundaries/{boundary_id}/"
        self.logger.debug(f"url={url}")
        boundary_delete = self._api_http_request(method="DELETE", url=url)
        if boundary_delete.status_code != httpx.codes.NO_CONTENT:
            self.logger.critical("STATUS CODE != 204")
            self.logger.critical(f"status_code={boundary_delete.status_code}")
            raise RuntimeError("boundary_delete issue", boundary_delete.text)

        if boundary_delete.status_code == httpx.codes.NO_CONTENT:
            return {"success": True}
        return {"success": False}

    def get_boundary(self, boundary_id: int) -> dict:
        """Get a boundary given a boundary_id.

        Parameters
        ----------
        boundary_id : int
            The ID of the boundary tool to retrieve.

        Returns
        -------
            boundary : dict

        Notes
        -----
        The cloud must be running at version >=R-23.3-S182.
        """
        if boundary_id is None:
            raise ValueError("Need a boundary_id to continue")

        url = self.TENANT_BASE_URL + f"v1/boundaries/{boundary_id}/"

        self.logger.debug(f"url={url}")
        boundary_details = self._api_http_request(method="GET", url=url)

        if boundary_details.status_code != httpx.codes.OK:
            self.logger.critical("STATUS CODE != 200")
            self.logger.critical(f"status_code={boundary_details.status_code}")
            self.logger.critical(f"text={boundary_details.text}")

        return self._json_decoder.decode(boundary_details.text)["data"]

    def get_boundaries(self) -> dict:
        """Get a list of boundaries.

        Returns
        -------
        boundaries : dict
            A dict of boundaries with the boundary_id as the key

        Notes
        -----
        The cloud must be running at version >=R-23.3-S182.
        """
        url = self.TENANT_BASE_URL + "v1/boundaries/"
        params = {
            "from": 0,
            "length": self.ARMIS_API_PAGE_SIZE,
            "includeTotal": "true",
        }
        boundaries = {}

        while params["from"] is not None:
            self.logger.debug(f"url={url}")
            boundaries_details = self._api_http_request(
                method="GET",
                url=url,
                params=params,
            )

            if boundaries_details.status_code != httpx.codes.OK:
                self.logger.critical("STATUS CODE != 200")
                self.logger.critical(f"status_code={boundaries_details.status_code}")
                self.logger.critical(f"text={boundaries_details.text}")

            if "boundaries" in self._json_decoder.decode(boundaries_details.text)["data"]:
                for boundary in self._json_decoder.decode(boundaries_details.text)["data"]["boundaries"]:
                    boundaries[boundary["id"]] = boundary
            params["from"] = self._json_decoder.decode(boundaries_details.text)["data"]["next"]

        return boundaries

    def update_boundary(self, **kwargs) -> None:
        """Update a boundary given a boundary_id.

        Parameters
        ----------
        boundary_id : int
            Armis boundary_id
        name : str
            new name of the boundary
        affected_sites : str | list, optional
            sites affected
        ruleaql : dict
            ASQ to define the boundary

        Notes
        -----
        The cloud must be running at version >=R-23.3-S182.
        """
        self.logger.debug(f"kwargs={kwargs}")

        boundary_id = kwargs.get("boundary_id")
        if boundary_id is None:
            raise ValueError("No boundary_id provided")

        name = kwargs.get("name")
        affected_sites = kwargs.get("affected_sites")
        ruleaql = kwargs.get("ruleaql")

        boundary_update_payload = {}
        if name is not None:
            boundary_update_payload["name"] = name

        if affected_sites is not None:
            if isinstance(affected_sites, list):
                self.logger.debug(
                    "affected_types was list, converting to a comma-delimited str",
                )
                # check if there is a comma in the name
                # we can't update a boundary using an affected site with a comma in it
                for affected_site in affected_sites:
                    if "," in affected_site:
                        raise ValueError(
                            "Site '" + affected_site + "' contains a comma - Armis API doesn't support this",
                        )
                    boundary_update_payload["affectedSites"] = affected_sites

                affected_sites = ",".join(affected_sites)

            boundary_update_payload["affectedSites"] = affected_sites

            if ruleaql is not None:
                boundary_update_payload["ruleAql"] = ruleaql

        # if not provided, fetch it from the cloud so we can round-trip it
        # back to the cloud
        if "name" not in boundary_update_payload or "ruleAql" not in boundary_update_payload:
            boundaryfromcloud = self.get_boundary(boundary_id=boundary_id)
            for key in ["name", "ruleAql"]:
                if key not in boundary_update_payload:
                    self.logger.debug(f'"{key}" not in payload, adding it')
                    boundary_update_payload[key] = boundaryfromcloud[key]

        self.logger.debug(f"payload is now {boundary_update_payload}")

        # PATCH the boundary
        url = self.TENANT_BASE_URL + f"v1/boundaries/{boundary_id}/"
        self.logger.debug(f"url={url}")
        boundary_update = self._api_http_request(
            method="PATCH",
            url=url,
            json=boundary_update_payload,
        )
        self.logger.debug(f"return text={boundary_update.text}")
        self.logger.debug(f"status_code={boundary_update.status_code}")
        if boundary_update.status_code != httpx.codes.OK:
            self.logger.info(f"FAILED boundary update for boundary_id={boundary_id}")
            self.logger.debug(boundary_update.text)
            raise RuntimeError("boundary update issue", boundary_update.text)

    def get_collector(self, collector_id: int) -> dict:
        """Get a collector given the collector_id.

        Parameters
        ----------
        collector_id: int
            The collector ID to fetch details about.

        Returns
        -------
        collectors_dict: dict
            A dictionary of a collector.
        """
        if collector_id is None:
            raise ValueError("collector_id is required")

        self.logger.info(f"collector_id={collector_id}")
        url = self.TENANT_BASE_URL + f"v1/collectors/{collector_id}/"

        self.logger.debug(f"url={url}")
        collector_request = self._api_http_request(method="GET", url=url)
        if collector_request.status_code != httpx.codes.OK:
            raise RuntimeError("collector issue", collector_request.text)

        return self._json_decoder.decode(collector_request.text)["data"]

    def get_collectors(self) -> dict:
        """Get a dictionary of collectors.

        Returns
        -------
        collectors_inventory: dict
            A dictionary of collectors.

        """
        url = self.TENANT_BASE_URL + "v1/collectors/"
        params = {
            "from": 0,
            "length": self.ARMIS_API_PAGE_SIZE,
        }
        collectors_inventory = {}

        while params["from"] is not None:
            self.logger.info(f'fetching {params["from"]}-{params["from"] + self.ARMIS_API_PAGE_SIZE}')

            get_collectors_request = self._api_http_request(
                method="GET",
                url=url,
                params=params,
            )
            if get_collectors_request.status_code != httpx.codes.OK:
                self.logger.critical("STATUS CODE != 200")
                self.logger.critical(f"status_code={get_collectors_request.status_code}")
                self.logger.critical(f"text={get_collectors_request.text}")
                self.logger.critical("continuing")
                continue

            collectors_response = self._json_decoder.decode(get_collectors_request.text)
            collectors_count = collectors_response["data"]["count"]
            self.logger.debug(f"retrieved {collectors_count} collectors")

            for collector in collectors_response["data"]["collectors"]:
                collectornumber = collector["collectorNumber"]
                collectors_inventory[collectornumber] = collector

            self.logger.debug(f'collectors next={collectors_response["data"]["next"]}')

            params["from"] = collectors_response["data"]["next"]

        self.logger.debug(f"collectors_inventory size={len(collectors_inventory)}")

        if len(collectors_inventory) > 0:
            collectors_inventory = dict(sorted(collectors_inventory.items()))
        return collectors_inventory

    def get_collectors_count(self) -> int:
        """Get a count of collectors.

        Returns
        -------
        collectors_count: int
            A count of collectors.

        """
        self.logger.info("get_collectors_count")
        url = self.TENANT_BASE_URL + "v1/collectors/"
        self.logger.debug(f"url={url}")
        params = {
            "length": 1,
        }
        collectors_count_request = self._api_http_request(
            method="GET",
            url=url,
            params=params,
        )
        collectors_count = int(
            self._json_decoder.decode(collectors_count_request.text)["data"]["total"],
        )
        self.logger.debug(f"collectors_count={collectors_count}")
        return collectors_count

    def rename_collector(self, collector_id: int, new_name: str) -> dict:
        """Rename a collector given the collector_id.

        Parameters
        ----------
        collector_id: int
            The collector ID to rename
        new_name: str
            New name of the collector

        Returns
        -------
        dict
            JSON data as a dict.
        """
        # patch
        url = self.TENANT_BASE_URL + f"v1/collectors/{collector_id}/"

        rename_collector_payload = {
            "name": new_name,
        }
        collector_update = self._api_http_request(
            method="PATCH",
            url=url,
            json=rename_collector_payload,
        )
        self.logger.debug(f"return text={collector_update.text}")
        self.logger.debug(f"status_code={collector_update.status_code}")
        if collector_update.status_code != httpx.codes.OK:
            self.logger.info(f"FAILED collector rename for collector_id={collector_id}, new_name={new_name}")
            self.logger.debug(collector_update.text)
            raise RuntimeError("collector rename issue", collector_update.text)

        return self._json_decoder.decode(collector_update.text)

    def get_devices(self, asq: str, **kwargs: dict) -> list:
        """Get devices from inventory matching ASQ.

        Parameters
        ----------
        asq : str
            ASQ to execute.
        fields_wanted : list
            List of fields wanted.

        Returns
        -------
        inventory : list
            Inventory items matching ASQ.
        """
        get_devices_start = pendulum.now()

        if asq is None:
            raise ValueError("no asq provided")
        self.logger.info(f"asq={asq}")

        fields_wanted = kwargs.get("fields_wanted", [])
        self.logger.info(f"fields_wanted={fields_wanted}")

        url = self.TENANT_BASE_URL + "v1/devices/"
        params = {
            "search": asq,
            "from": 0,
            "length": self.ARMIS_API_PAGE_SIZE,
            "fields": ",".join(fields_wanted),
        }

        # NOTE:
        # From the API Guide v1.8:
        # "Iterating over a set of results it is recommended best practice to
        # orderBy a fixed parameter (deviceId for example) in order to not to
        # miss data between pages. This is because the default order is by
        # lastSeen, so results can change."
        params["orderBy"] = "id"

        inventory = []
        inventory_total = self.get_devices_count(asq=asq)
        self.logger.debug(f"inventory_total={inventory_total}")

        if inventory_total == 0:
            return []

        remaining_time = -1
        filenames = []
        filenumber = 1

        while params["from"] is not None:
            page_fetch_start = pendulum.now()
            self.logger.info(
                f'fetching {params["from"]}-{params["from"] + self.ARMIS_API_PAGE_SIZE} '
                f'of a total of {inventory_total}',
            )
            device_details = self._api_http_request(
                method="GET",
                url=url,
                params=params,
            )

            if device_details.status_code != httpx.codes.OK:  # pragma: no cover
                self.logger.critical("STATUS CODE != 200")  # pragma: no cover
                self.logger.critical(f"status_code={device_details.status_code}")
                self.logger.critical(f"text={ device_details.text}")
                self.logger.critical("continuing")
                continue

            devices = self._json_decoder.decode(device_details.text)

            if len(devices["data"]["data"]) > 0:
                fetchedcolumns = list(devices["data"]["data"][0].keys())
                self.logger.debug(f"Fetched columns={fetchedcolumns}")
                setdiff = set(fields_wanted).difference(fetchedcolumns)
                if len(setdiff) > 0:
                    self.logger.info(f"Fields missing from wanted columns={list(setdiff)}")
                    raise ValueError(
                        "Fields wanted="
                        + ",".join(fields_wanted)
                        + "\nFields fetched="
                        + ",".join(fetchedcolumns)
                        + "\nFields missing from wanted columns="
                        + ",".join(list(setdiff)),
                    )
            else:
                self.logger.debug(f"can't find fields, return from this iteration={devices}")  # pragma: no cover
                return []  # pragma: no cover

            now = pendulum.now()
            filename = pl.Path(
                str(self.temporary_directory.name) + "/" + f"devices_{now.float_timestamp}.json.gz",
            )

            self.logger.info(f"devices filename={filename}")
            # using default zlib compression level (i.e. -1 AKA 6)
            filename.write_bytes(gzip.compress(device_details.content))
            filenames.append(filename)
            filenumber += 1

            now = pendulum.now()
            self.logger.debug(f"now={now}")
            self.logger.debug(f"get_devices_start={get_devices_start}")

            total_elapsed_time = now.timestamp() - get_devices_start.timestamp()
            self.logger.debug(f"total_elapsed_time={total_elapsed_time}")

            page_fetch_time = now.timestamp() - page_fetch_start.timestamp()
            self.logger.info(f"page fetch time={page_fetch_time}")

            # if the page_fetch_time exceeds 90% of the http timeout,
            # start reducing the size of our pages so we can fit the page request
            # into the http timeout period.
            if page_fetch_time > self._http_timeout * 0.9:
                self.ARMIS_API_PAGE_SIZE = self._ceiling_up(
                    self.ARMIS_API_PAGE_SIZE * 0.90,
                    100,
                )  # pragma: no cover
                params["length"] = self.ARMIS_API_PAGE_SIZE  # pragma: no cover

                self.logger.info(
                    f"page_fetch_time > {int(self._http_timeout * 0.9)}, "
                    f"reducing page size by 10% to {self.ARMIS_API_PAGE_SIZE}",
                )

            if params["from"] > 0:
                time_per_device = total_elapsed_time / params["from"]  # pragma: no cover
                self.logger.debug(f"time_per_device={time_per_device}")  # pragma: no cover

                remaining_devices = inventory_total - params["from"]  # pragma: no cover
                self.logger.debug(f"remaining_devices={remaining_devices}")  # pragma: no cover

                remaining_time = remaining_devices * time_per_device  # pragma: no cover
                self.logger.debug(f"remaining_time={remaining_time}")  # pragma: no cover

            if remaining_time < 0:  # noqa: SIM108
                estimated_end_time = now
            else:
                estimated_end_time = now.add(seconds=remaining_time)  # pragma: no cover

            self.logger.info(f"estimated_end_time={estimated_end_time}")

            params["from"] = devices["data"]["next"]

        # reproduce inventory here
        for filename in filenames:
            self.logger.info(f"reading {filename.name}")
            j = self._json_decoder.decode(gzip.decompress(filename.read_bytes()))
            self.logger.info(f'appending {len(j["data"]["data"])} records')
            inventory.extend(j["data"]["data"])

        self.logger.debug(f"inventory size={len(inventory)}")

        return inventory

    def get_devices_count(self, asq: str) -> int:
        """Get count of devices matching ASQ.

        Parameters
        ----------
        asq : str
            ASQ to execute.

        Returns
        -------
        device_count : int
            Count of devices matching ASQ.
        """
        if asq is None:
            raise ValueError("asq is required")
        self.logger.info(f"asq={asq}")

        url = self.TENANT_BASE_URL + "v1/devices/"
        params = {
            "search": asq,
            "length": 1,
            "from": 0,
            "fields": "id",
        }
        self.logger.debug(f"url={url}")

        inventory_total_request = self._api_http_request(method="GET", url=url, params=params)
        if inventory_total_request.status_code != httpx.codes.OK:
            raise RuntimeError(
                "inventory issue",
                inventory_total_request.text,
            )  # pragma: no cover

        inventory_total = int(
            self._json_decoder.decode(inventory_total_request.text)["data"]["total"],
        )
        self.logger.info(f"inventory_total={inventory_total}")
        return inventory_total

    def tag_device(self, **kwargs: dict) -> None:
        """Add or remove a device from a deviceid.

        Parameters
        ----------
        device_id : int
            Device ID to tag.
        tags : list | str
            Tags to add to or remove from the device ID.
        action : {'add', 'remove'}
            Action to perform, one of add or remove.
        """
        self.logger.debug("tag_device")
        device_id = kwargs.get("device_id")
        if device_id is None:
            raise ValueError("no device_id specified")

        self.logger.debug(f"device_id={device_id}")

        tags = kwargs.get("tags", [])
        self.logger.debug(f"tags type={type(tags)}")

        if isinstance(tags, str):
            self.logger.debug("type was string, converting to list")
            tags = [tags]

        self.logger.debug(f"tags={tags}")
        action: str = kwargs.get("action", "add")
        action = str(action).lower()
        self.logger.debug(f"action={action}")

        if len(tags) == 0:
            raise ValueError("no tag provided")

        if action not in {"add", "remove"}:
            raise ValueError("no valid action provided, should be one of add or remove")

        url = self.TENANT_BASE_URL + f"v1/devices/{device_id}/tags/"

        self.logger.debug(f"url={url}")

        tag_payload = {"tags": tags}
        self.logger.debug(f"json currently={tag_payload}")
        self.logger.info(f"tagging, action={action}, deviceid={device_id}, tags={tags}")

        if action == "add":
            tag_device_update = self._api_http_request(
                method="POST",
                url=url,
                json=tag_payload,
            )
        if action == "remove":
            tag_device_update = self._api_http_request(
                method="DELETE",
                url=url,
                json=tag_payload,
            )

        self.logger.debug(f"return text={tag_device_update.text}")
        self.logger.debug(f"status_code={tag_device_update.status_code}")
        if tag_device_update.status_code != httpx.codes.OK:
            self.logger.info(f"FAILED DEVICE TAG for device_id={device_id}")
            self.logger.debug(tag_device_update.text)
            raise RuntimeError("tag_device_update issue", tag_device_update.text)

        return tag_device_update.text

    def create_integration(self, **kwargs: dict) -> dict:
        """Create an integration.

        Parameters
        ----------
        collector_id : int
            ID of the collector
        integration_name : str
            name of the integration
        integration_type : str
            the type of integration
        integration_params : dict
            integration-specific parameters

        Returns
        -------
        status : dict
            Status of action as returned by the cloud

        Notes
        -----
        This method requires v2 of the API call which is only available in the
        Armis Cloud version >=R-24.0.

        Examples
        --------
        From the Armis online Swagger documentation, the payload looks like this:

        ```
        {
            "collectorId": 1,
            "instance": "My Integration",
            "name": "SPAN/TAP",
            "params": {"sniff_interface": "eno1"},
        }
        ```

        """
        collector_id = kwargs.get("collector_id")
        integration_name = kwargs.get("integration_name")
        integration_type = kwargs.get("integration_type")
        integration_params = kwargs.get("integration_params")

        if collector_id is None or integration_name is None or integration_params is None or integration_type is None:
            raise ValueError(
                "no collector_id, integration_name, integrations_params, or integration_type",
            )

        url = self.TENANT_BASE_URL + "v2/integrations/"

        # from the Armis API documentation
        integration_payload = {
            "collectorId": collector_id,
            "instance": integration_name,
            "name": integration_type,
            "params": integration_params,
        }

        self.logger.debug(f"data to be posted={integration_payload}")
        create_integration_request = self._api_http_request(
            method="POST",
            url=url,
            json=integration_payload,
        )

        return self._json_decoder.decode(create_integration_request.text)

    def get_integration(self, integration_id: int):
        """Get an integration given an integration_id.

        Parameters
        ----------
        integration_id : int
            Desired integration_id

        Returns
        -------
        integration : dict
            a dictionary of the requested integration

        Notes
        -----
        This method requires v2 of the API call which is only available in the
        Armis Cloud version >=R-24.0.
        """
        if integration_id is None:
            raise ValueError("an integration_id is required")

        url = self.TENANT_BASE_URL + f"v2/integrations/{integration_id}/"

        integration_details = self._api_http_request(method="GET", url=url)

        if integration_details.status_code == httpx.codes.NOT_FOUND:
            self.logger.debug("integration was not found")
            self.logger.debug(f"text={integration_details.text}")
            return {}

        if integration_details.status_code != httpx.codes.OK:
            self.logger.critical(f"STATUS CODE={integration_details.status_code}")
            self.logger.debug(f"status_code={integration_details.status_code}")
            self.logger.debug(f"text={integration_details.text}")
            raise RuntimeError("integration_details issue", integration_details.text)

        integration = self._json_decoder.decode(integration_details.text)["data"][0]
        return integration  # noqa: RET504

    def get_integrations(self) -> dict:
        """Get a list of integrations.

        Returns
        -------
        integrations : dict
            a dictionary of integrations

        Notes
        -----
        This method requires v2 of the API call which is only available in the
        Armis Cloud version >=R-24.0.
        """
        url = self.TENANT_BASE_URL + "v2/integrations/"
        params = {
            "from": 0,
            "length": self.ARMIS_API_PAGE_SIZE,
        }

        integrations_count = self.get_integrations_count()

        integrations = {}

        while params["from"] is not None:
            self.logger.info(
                f'fetching {params["from"]}-{params["from"] + self.ARMIS_API_PAGE_SIZE} '
                f'of a total of {integrations_count}',
            )

            self.logger.debug(f"url={url}")
            integrations_details = self._api_http_request(
                method="GET",
                url=url,
                params=params,
            )

            if integrations_details.status_code != httpx.codes.OK:
                self.logger.critical("STATUS CODE != 200")
                self.logger.critical(f"status_code={integrations_details.status_code}")
                self.logger.critical(f"text={integrations_details.text}")
                raise RuntimeError(
                    "integrations_details issue",
                    integrations_details.text,
                )

            for integration in self._json_decoder.decode(integrations_details.text)["data"]["integrations"]:
                integrationid = integration["id"]
                integrations[integrationid] = integration

            params["from"] = self._json_decoder.decode(integrations_details.text)["data"]["next"]

        if len(integrations) > 0:
            return integrations

        return []

    def get_integrations_count(self) -> int:
        """Get count of integrations.

        Returns
        -------
        integrations_count : int
            A count of integrations.

        Notes
        -----
        This method requires v2 of the API call which is only available in the
        Armis Cloud version >=R-24.0.
        """
        url = self.TENANT_BASE_URL + "v2/integrations/"
        params = {
            "length": 1,
        }

        self.logger.debug(f"url={url}")
        count_request = self._api_http_request(
            method="GET",
            url=url,
            params=params,
        )
        return int(self._json_decoder.decode(count_request.text)["data"]["total"])

    def delete_integration(self, integration_id: int) -> dict:
        """Delete an integration given the integration_id.

        Parameters
        ----------
        integration_id : int
            An integration_id to delete.

        Returns
        -------
        delete_integration_result : dict
            Result of the delete action, directly from the cloud.
        """
        url = self.TENANT_BASE_URL + f"v2/integrations/{integration_id}/"
        self.logger.debug(f"url={url}")
        integration_delete = self._api_http_request(method="DELETE", url=url)
        if integration_delete.status_code != httpx.codes.OK:
            self.logger.critical("STATUS CODE !=200")
            self.logger.critical(f"status_code={integration_delete.status_code}")
            self.logger.critical(f"text={integration_delete.text}")
            raise RuntimeError("integration_details issue", integration_delete.text)

        return self._json_decoder.decode(integration_delete.text)

    def get_search(self, asq: str, **kwargs: dict) -> dict:
        """Return search result for given ASQ string.

        Parameters
        ----------
        asq : str
            ASQ search string
        fields_wanted : list
            List of fields wanted.

        Returns
        -------
        records: list
            Records matching ASQ

        Notes
        -----
        This is different from the `get_devices` method, which only allows
        you to retrieve devices.  This method allows you to retrieve data
        with any valid ASQ, including records from `in:devices` queries.
        """
        get_search_start = pendulum.now()

        self.logger.info(f"asq={asq}")
        fields_wanted: list = kwargs.get("fields_wanted", [])
        if isinstance(fields_wanted, str):
            fields_wanted = [fields_wanted]
        self.logger.info(f"fields_wanted={fields_wanted}")

        url = self.TENANT_BASE_URL + "v1/search/"
        params = {
            "aql": asq,
            "from": 0,
            "length": self.ARMIS_API_PAGE_SIZE,
        }

        if len(fields_wanted) > 0:
            params["fields"] = ",".join(fields_wanted)

        records = []
        records_total = self.get_search_count(asq=asq)
        remaining_time = -1

        filenames = []
        filenumber = 1

        while params["from"] is not None:
            self.logger.info(
                f'fetching {params["from"]}-{params["from"] + self.ARMIS_API_PAGE_SIZE} '
                f'of a total of {records_total}',
            )
            search_details = self._api_http_request(
                method="GET",
                url=url,
                params=params,
            )

            if search_details.status_code != httpx.codes.OK:
                self.logger.critical("STATUS CODE !=200")
                self.logger.critical(f"status_code={search_details.status_code}")
                self.logger.critical(f"text={search_details.text}")
                self.logger.critical("continuing")
                continue

            data = self._json_decoder.decode(search_details.text)
            totalresults = data["data"]["total"]
            if totalresults == 0:
                return []

            if len(data["data"]["results"]) > 0:
                fetchedcolumns = list(data["data"]["results"][0].keys())
                self.logger.debug(f"Fetched columns={fetchedcolumns}")
                setdiff = set(fields_wanted).difference(fetchedcolumns)
                if len(setdiff) > 0:
                    self.logger.info(
                        f"Fields missing from wanted columns={setdiff}",
                    )
                    raise ValueError(
                        "Fields wanted="
                        + ",".join(fields_wanted)
                        + "\nFields fetched="
                        + ",".join(fetchedcolumns)
                        + "\nFields missing from wanted columns="
                        + ",".join(list(setdiff)),
                    )
            else:
                self.logger.debug(f"no data, data={data}")
                return []

            now = pendulum.now()
            filename = pl.Path(
                str(self.temporary_directory.name) + "/" + f"search_results_{now.float_timestamp}.json.gz",
            )
            self.logger.info(f"search_results filename={filename}")
            # using default zlib compression level (i.e. -1 AKA 6)
            filename.write_bytes(gzip.compress(search_details.content))
            filenames.append(filename)
            filenumber += 1

            now = pendulum.now()
            self.logger.debug(f"now={now}")
            self.logger.debug(f"get_search_start={get_search_start}")

            elapsed_time = now.timestamp() - get_search_start.timestamp()
            self.logger.debug(f"elapsed_time={elapsed_time}")

            if params["from"] > 0:
                time_per_record = elapsed_time / params["from"]
                self.logger.debug(f"time_per_record={time_per_record}")

                remaining_records = records_total - params["from"]
                self.logger.debug(f"remaining_records={remaining_records}")

                remaining_time = remaining_records * time_per_record
                self.logger.debug(f"remaining_time={remaining_time}")

            if remaining_time < 0:  # noqa: SIM108
                estimated_end_time = now
            else:
                estimated_end_time = now.add(seconds=remaining_time)

            self.logger.info(f"estimated_end_time={estimated_end_time}")

            params["from"] = data["data"]["next"]

        # reproduce inventory here
        for filename in filenames:
            self.logger.info(f"reading filename={filename.name}")
            j = self._json_decoder.decode(gzip.decompress(filename.read_bytes()))
            self.logger.info(f'appending {len(j["data"])} records')
            records.extend(j["data"]["results"])

        self.logger.debug(f"records size={len(records)}")

        # clean up tmpdirectory
        for filename in filenames:
            filename.unlink(missing_ok=True)

        if len(records) > 0:
            return records

        return []

    def get_search_count(self, asq: str) -> int:
        """Get a count of records using ASQ.

        Parameters
        ----------
        asq : str
            ASQ to search for records.

        Returns
        -------
        count: int
            A count of records matching ASQ.
        """
        self.logger.info(f"asq={asq}")
        url = self.TENANT_BASE_URL + "v1/search/"

        # Armis still calls this AQL in their API
        params = {
            "aql": asq,
            "length": 1,
            "from": 0,
            "fields": "id",
        }

        search_total_request = self._api_http_request(
            method="GET",
            url=url,
            params=params,
        )
        if search_total_request.status_code != httpx.codes.OK:
            raise RuntimeError("search retults issue", search_total_request.text)

        search_total = int(
            self._json_decoder.decode(search_total_request.text)["data"]["total"],
        )
        self.logger.info(f"search_total={search_total}")
        return search_total

    def get_sites(self) -> dict:
        """Get a list of sites.

        Returns
        -------
        sites : dict
            A dict of sites.

        Notes
        -----
        The cloud must be running at version >=R-23.3-S182.
        """
        url = self.TENANT_BASE_URL + "v1/sites/"
        params = {
            "from": 0,
            "length": self.ARMIS_API_PAGE_SIZE,
            "includeTotal": "true",
        }

        sites = {}
        while params["from"] is not None:
            self.logger.debug(f"url={url}")
            sites_details = self._api_http_request(
                method="GET",
                url=url,
                params=params,
            )

            if sites_details.status_code != httpx.codes.OK:
                self.logger.critical("STATUS CODE != 200")
                self.logger.critical(f"status_code={sites_details.status_code}")
                self.logger.critical(f"text={sites_details.text}")

            if "sites" in self._json_decoder.decode(sites_details.text)["data"]:
                for site in self._json_decoder.decode(sites_details.text)["data"]["sites"]:
                    sites[site["id"]] = site

            params["from"] = self._json_decoder.decode(sites_details.text)["data"]["next"]

        return sites

    def get_site(self, **kwargs) -> dict:
        """Get a site with a given site_id.

        Parameters
        ----------
        site_id : int
            The site ID to fetch details about.

        Returns
        -------
        dict
            JSON data as a dict.
        """
        site_id = kwargs.get("site_id")

        if site_id is None:
            raise ValueError("site_id was not provided")

        url = self.TENANT_BASE_URL + f"v1/sites/{site_id}/"

        self.logger.debug(f"url={url}")

        site_request = self._api_http_request(method="GET", url=url)
        if site_request.status_code != httpx.codes.OK:
            self.logger.critical("STATUS CODE !=200")
            self.logger.critical(f"status_code={site_request.status_code}")
            self.logger.critical(f"text={site_request.text}")
            self.logger.critical("continuing")
            raise RuntimeError("dashboard http response !=200")

        if "data" in self._json_decoder.decode(site_request.text):
            return self._json_decoder.decode(site_request.text)["data"]
        return {}

    def delete_user(self, user_id_or_email):
        """Delete a user given the user_id or email.

        Parameters
        ----------
        user_id_or_email : str|int
            A user_id (int) or email (str) to delete.

        Returns
        -------
        delete_user_result : str
            Text from the output of the delete action.
        """
        url = self.TENANT_BASE_URL + f"v1/users/{user_id_or_email}/"
        self.logger.debug(f"url={url}")

        user_delete = self._api_http_request(method="DELETE", url=url)
        self.logger.debug(f"return text={user_delete.text}")
        self.logger.debug(f"status_code={user_delete.status_code}")
        if user_delete.status_code != httpx.codes.OK:
            self.logger.info(f"FAILED USER UPDATE for user={user_id_or_email}")
            self.logger.debug(user_delete.text)
            raise RuntimeError("delete user issue", user_delete.text)

        return self._json_decoder.decode(user_delete.text)

    def edit_user(self, user_id_or_email: str | int, **kwargs: dict) -> dict:
        """Edit a user given the user_id or email.

        Parameters
        ----------
        user_id_or_email : str|int
            user_id (int) or email (str) to change
        email : str
            email address of the user
        location : str
            Location of the user
        name : str
            Name of user
        phone : str
            Phone number of user
        roleassignment : list
            List of roles the user should be assigned to
        title : str
            Title of the user
        username : str
            username of the user

        Returns
        -------
        user_update_result : dict
            A dictionary of the edited user details
        """
        # attributes that are required: email, roleassignment, and username
        # first use what was provided via the method and then fetch
        # all missing data from the cloud

        if len(kwargs) == 0:
            raise ValueError("Need a field to be changed")

        need_data_from_cloud = False

        required_attributes = ["email", "roleAssignment", "username"]
        optional_attributes = ["location", "name", "phone", "title"]
        edit_user_dict = {}

        if "@" in str(user_id_or_email):
            edit_user_dict["email"] = user_id_or_email
        else:
            edit_user_dict["email"] = None

        for required_attribute in required_attributes:
            if edit_user_dict.get(required_attribute) is None:
                edit_user_dict[required_attribute] = kwargs.get(required_attribute)
        if None in list(edit_user_dict.values()):
            need_data_from_cloud = True

        if need_data_from_cloud:
            try:
                existinguser = self.get_user(user_id_or_email=user_id_or_email)
            except RuntimeError as e:
                raise RuntimeError(e) from e
            for required_attribute in required_attributes:
                if edit_user_dict[required_attribute] is None:
                    edit_user_dict[required_attribute] = existinguser[required_attribute]
        for optional_attribute in optional_attributes:
            optional_attribute_value = kwargs.get(optional_attribute)
            if optional_attribute_value is not None:
                edit_user_dict[optional_attribute] = optional_attribute_value

        self.logger.debug(f"edit_user_dict is now={edit_user_dict}")
        # when updating, roleassignment and username are required
        url = self.TENANT_BASE_URL + f"v1/users/{user_id_or_email}/"
        user_update = self._api_http_request(
            method="PATCH",
            url=url,
            json=edit_user_dict,
        )
        self.logger.debug(f"return text={user_update.text}")
        self.logger.debug(f"status_code={user_update.status_code}")
        if user_update.status_code != httpx.codes.OK:
            self.logger.info(f"FAILED USER UPDATE for user={user_id_or_email}")
            self.logger.debug(user_update.text)
            raise RuntimeError("edit user issue", user_update.text)

        return self._json_decoder.decode(user_update.text)

    def get_user(self, user_id_or_email, **kwargs):
        """Get a user by user_id or email.

        Parameters
        ----------
        user_id_or_email : str | int
            The user_id or email of the user to retrieve.
        fields: list
            The list of fields to retrieve.

        Returns
        -------
        userdetails: dict
            A dictionary of user information.
        """
        if len(str(user_id_or_email)) < 1:
            raise ValueError("missing user_id_or_email")

        fields = kwargs.get("fields", [])
        if isinstance(fields, str):
            fields = [fields]

        params = {}

        url = self.TENANT_BASE_URL + f"v1/users/{user_id_or_email}/"
        if len(fields) > 0:
            params["fields"] = ",".join(fields)

        self.logger.debug(f"url={url}")

        user_details = self._api_http_request(
            method="GET",
            url=url,
            params=params,
        )

        if user_details.status_code != httpx.codes.OK:
            self.logger.critical("STATUS CODE !=200")
            self.logger.critical(f"status_code={user_details.status_code}")
            self.logger.critical(f"text={user_details.text}")
            raise RuntimeError(user_details.text)

        data = self._json_decoder.decode(user_details.text)
        success_status = data["success"]
        if success_status is True:
            return data["data"]

        raise RuntimeError(user_details.text)

    def get_users(self) -> dict:
        """Get a list of users.

        Returns
        -------
        users : dict
            A dictionary of users.
        """
        url = self.TENANT_BASE_URL + "v1/users/"
        self.logger.debug(f"url={url}")
        users_details = self._api_http_request(
            method="GET",
            url=url,
        )

        if users_details.status_code != httpx.codes.OK:
            self.logger.critical("STATUS CODE !=200")
            self.logger.critical(f"status_code={users_details.status_code}")
            self.logger.critical(f"text={users_details.text}")
            raise RuntimeError("users_details issue", users_details.text)

        users = {}
        data = self._json_decoder.decode(users_details.text)
        if "users" in data["data"]:
            for user in data["data"]["users"]:
                users[user["id"]] = user

        return users
