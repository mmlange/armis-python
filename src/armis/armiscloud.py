#!/usr/bin/python3

# SPDX-FileCopyrightText: 2024-present Matthew Lange <mmlange@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

import contextlib
import gzip
import logging
import logging.handlers
import math
import pathlib as pl
import tempfile
import warnings

import httpx
import msgspec
import pendulum
from furl import furl
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
        self.log = logging.getLogger("Armis")
        self.log.setLevel(logging.INFO)
        log_level = kwargs.get("log_level", "INFO")
        self.log.info("log_level=%s", str(log_level))

        if log_level not in logging._nameToLevel:
            self.log.info("log level not found, setting to info")
            warnings.warn(
                "log level not found, setting to info",
                stacklevel=2,
            )

            self.log.setLevel(logging.INFO)
        else:
            logging_log_level = logging.getLevelName(log_level)
            self.log.info(
                "logging log level looked up and is=%s",
                str(logging_log_level),
            )
            self.log.setLevel(logging_log_level)

        self._authorization_token = 0
        self._authorization_token_expiration = 0

        self.temporary_directory = kwargs.get("temporary_directory", None)
        if self.temporary_directory is None:
            self.temporary_directory = tempfile.TemporaryDirectory()

        self.log.info("temporary_directory=%s", str(self.temporary_directory.name))

        self._http_timeout: int = 100

        self.ARMIS_API_PAGE_SIZE: int = kwargs.get(
            "api_page_size",
            self.ARMIS_MAXIMUM_API_PAGE_SIZE,
        )
        if self.ARMIS_API_PAGE_SIZE > self.ARMIS_MAXIMUM_API_PAGE_SIZE:
            self.log.info(
                "page size requested=%s, page size maximum is=%s",
                self.ARMIS_API_PAGE_SIZE,
                self.ARMIS_MAXIMUM_API_PAGE_SIZE,
            )
            warnings.warn(
                "page size requested="
                + str(self.ARMIS_API_PAGE_SIZE)
                + ", page size maximum="
                + str(self.ARMIS_MAXIMUM_API_PAGE_SIZE),
                stacklevel=2,
            )
        self.log.debug("api_page_size=%s", str(self.ARMIS_API_PAGE_SIZE))
        self.API_SECRET_KEY: str = kwargs.get("api_secret_key", None)
        if self.API_SECRET_KEY is None:
            raise ValueError("No secret key provided")

        self.HTTP_RETRY_MAX: int = 5
        self._httpx_limits = httpx.Limits(
            max_keepalive_connections=50,
            max_connections=200,
            keepalive_expiry=120,
        )
        self.httpx_client = self._get_httpx_client()

        tenant_hostname = kwargs.get("tenant_hostname", None)
        if tenant_hostname is None:
            raise ValueError("tenant_hostname is required")

        self.TENANT_BASE_URL = furl()
        self.TENANT_BASE_URL.scheme = "https"
        self.TENANT_BASE_URL.host = tenant_hostname
        self.TENANT_BASE_URL.path = "/api/"

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
        if not isinstance(number, (int, float)):  # noqa: UP038
            raise ValueError("number " + str(number) + " is not an int or float")
        if nearest is None:
            raise ValueError("nearest was not provided")

        return math.ceil(number / nearest) * nearest

    def _get_httpx_client(self):
        with contextlib.suppress(AttributeError):
            self.httpx_client.close()

        httpx_client = httpx.Client(
            follow_redirects=True,
            headers={
                "user-agent": f"Armis Python Library {__version__}",
            },
            http2=True,
            limits=self._httpx_limits,
            timeout=self._http_timeout,
            trust_env=False,
        )
        return httpx_client  # noqa: RET504

    def _api_http_request(self, **kwargs):
        """Wrap the request function and handles the authorization token.

        Parameters
        ----------
        method : str
            HTTP method, one of DELETE, GET, PATCH, POST, PUT, etc.
        url : str|furl
            the URL endpoint
        content : str, optional
            content to pass along
        headers : dict, optional
            headers to pass along
        json : dict, optional
            json to pass along
        params : str, optional
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
        self.log.debug("kwargs=%s", str(kwargs))

        method: str = kwargs.get("method", None)
        url = kwargs.get("url", None)
        content: str = kwargs.get("content", "")
        headers: dict = kwargs.get("headers", {})
        json: dict = kwargs.get("json", {})
        params: str = kwargs.get("params", "")
        maximum_retries: int = kwargs.get("maximum_retries", self.HTTP_RETRY_MAX)

        if len(content) > 0 and len(json) > 0:
            raise ValueError("You can send content or JSON, not both")

        if method is None or url is None:
            raise ValueError("no method or url")

        if isinstance(url, str):
            url = furl(url)

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
                self.log.info(
                    "ATTEMPT NUMBER %s of %s",
                    str(attempt.retry_state.attempt_number),
                    str(maximum_retries),
                )
                if attempt.retry_state.attempt_number > 1 and "length" in url.args:
                    self.log.info(
                        "attempt number >1, reducing page size, was %s",
                        str(url.args["length"]),
                    )
                    url.args["length"] = int(url.args["length"] * 0.75)
                    self.log.info(
                        "reducing page size, now %s",
                        str(url.args["length"]),
                    )

                self._update_authorization_token()

                if method == "GET":
                    self.log.debug("GETting URL=%s", str(url))
                    r = self.httpx_client.get(str(url), headers=headers, params=params)
                    self.log.debug("r.status_code=%s", str(r.status_code))
                if method == "POST":
                    if len(content) == 0 and len(json) == 0:
                        raise ValueError("You must send either content or JSON")
                    self.log.debug("POSTing URL=%s", str(url))
                    if len(json) > 0:
                        r = self.httpx_client.post(str(url), json=json, headers=headers)
                    elif len(content) > 0:
                        r = self.httpx_client.post(
                            str(url),
                            content=content,
                            headers=headers,
                        )

                    self.log.debug("r.status_code=%s", str(r.status_code))

                if method == "PATCH":
                    self.log.debug("PATCHing URL=%s", str(url))
                    if len(json) > 0:
                        r = self.httpx_client.patch(
                            str(url),
                            json=json,
                            headers=headers,
                        )
                    elif len(content) > 0:
                        r = self.httpx_client.patch(
                            str(url),
                            content=content,
                            headers=headers,
                        )

                    self.log.debug("r.status_code=%s", str(r.status_code))

                if method == "DELETE":
                    # NOTE: httpx_client.delete method doesn't work as you're
                    # not supposed to send data with a DELETE request.
                    # Instead, we'll use the generic request method to do this.
                    # See
                    # https://tinyurl.com/httpx-delete
                    self.log.debug("DELETEing URL=%s", str(url))
                    if len(json) > 0:
                        r = self.httpx_client.request(
                            "DELETE",
                            str(url),
                            json=json,
                            headers=headers,
                        )
                    elif len(content) > 0:
                        r = self.httpx_client.request(
                            "DELETE",
                            str(url),
                            content=content,
                            headers=headers,
                        )
                    else:
                        r = self.httpx_client.request(
                            "DELETE",
                            str(url),
                            headers=headers,
                        )

                self.log.debug("response http version=%s", str(r.http_version))

                try:
                    _ = self._json_decoder.decode(r.text)
                except msgspec.DecodeError as err:
                    self.log.critical("exception: %s", str(err))
                    self.log.debug("text of response=%s", r.text)
                    raise err

                self.log.debug("size of return text=%s", str(len(r.text)))
                if len(r.text) < 1000:
                    self.log.debug("return text=%s", r.text)

                return r

    def _update_authorization_token(self) -> None:
        """Fetch an authorization token.

        Check if the token we have is still valid.  If not, get a new token and
        stash it in the object and update the HTTPX client header.
        """
        self.log.debug("BEGIN")
        now = pendulum.now().timestamp()
        remaining_time = self._authorization_token_expiration - now
        self.log.debug("now=%s", str(now))
        self.log.debug("remaining_time=%s", str(remaining_time))

        if remaining_time < 1_000:
            self.log.debug("remaining_time < 1000")
            self.log.debug("expires=%s", str(self._authorization_token_expiration))
            self.log.debug("now > _authorization_token_expiration")
            self.log.debug("_authorization_token expired, getting new one")
            url = str(self.TENANT_BASE_URL / "v1/access_token/")
            r = self.httpx_client.post(
                url,
                data={
                    "secret_key": self.API_SECRET_KEY,
                },
            )
            returnjson = self._json_decoder.decode(r.text)
            self.log.info("returnjson=%s", str(returnjson))

            if "access_token" in returnjson["data"]:
                self._authorization_token = returnjson["data"]["access_token"]
                self.log.debug(
                    "RAW expiration_utc=%s",
                    str(returnjson["data"]["expiration_utc"]),
                )
                self._authorization_token_expiration = pendulum.parse(
                    returnjson["data"]["expiration_utc"],
                ).timestamp()
                self.log.debug("RAW authorization_token=%s", self._authorization_token)
                self.log.debug(
                    "parsed authorization_token_expiration=%s",
                    str(self._authorization_token_expiration),
                )
            else:
                self.log.debug("access_token=None")  # pragma: no cover
        else:
            self.log.debug("expires=%s", str(self._authorization_token_expiration))
            self.log.debug("now < _authorization_token_expiration")

        self.httpx_client.headers["Authorization"] = self._authorization_token

        self.log.debug("END")

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
        The cloud must be running at version >= R-23.3-S182.
        """
        # boundary_id = kwargs.get("boundary_id", None)

        if boundary_id is None:
            raise ValueError("Need a boundary_id to continue")

        url = self.TENANT_BASE_URL / "v1/boundaries" / str(boundary_id) / "/"
        self.log.debug("url=%s", str(url))
        boundary_details = self._api_http_request(method="GET", url=url)

        if boundary_details.status_code != httpx.codes.OK:
            self.log.critical("STATUS CODE != 200")
            self.log.critical("status_code=%s", str(boundary_details.status_code))
            self.log.critical("text=%s", boundary_details.text)

        return self._json_decoder.decode(boundary_details.text)["data"]

    def get_boundaries(self) -> dict:
        """Get a list of boundaries.  Only works for cloud version >= R-23.3-S182.

        Returns
        -------
        boundaries : dict
            A dict of boundaries with the boundary_id as the key
        """
        url = self.TENANT_BASE_URL / "v1/boundaries/"
        url.args["from"] = 0
        url.args["length"] = self.ARMIS_API_PAGE_SIZE
        url.args["includeTotal"] = "true"

        boundaries = {}

        while url.args["from"] is not None:
            self.log.debug("url=%s", str(url))
            boundaries_details = self._api_http_request(method="GET", url=url)

            if boundaries_details.status_code != httpx.codes.OK:
                self.log.critical("STATUS CODE != 200")
                self.log.critical("status_code=%s", str(boundaries_details.status_code))
                self.log.critical("text=%s", boundaries_details.text)

            if (
                "boundaries"
                in self._json_decoder.decode(boundaries_details.text)["data"]
            ):
                for boundary in self._json_decoder.decode(boundaries_details.text)[
                    "data"
                ]["boundaries"]:
                    boundaries[boundary["id"]] = boundary
            url.args["from"] = self._json_decoder.decode(boundaries_details.text)[
                "data"
            ]["next"]

        return boundaries

    def update_boundary(self, **kwargs) -> None:
        """Update a boundary given a boundary_id.

        Parameters
        ----------
        boundary_id : int
            Armis boundary_id
        name : str
            new name of the boundary
        affected_sites : str|list, optional
            sites affected
        ruleaql : dict
            ASQ to define the boundary

        Notes
        -----
        Only applies to cloud version >= R-23.3-S182.
        """
        self.log.debug("kwargs=%s", str(kwargs))

        boundary_id = kwargs.get("boundary_id", None)
        if boundary_id is None:
            raise ValueError("No boundary_id provided")

        name = kwargs.get("name", None)
        affected_sites = kwargs.get("affected_sites", None)
        ruleaql = kwargs.get("ruleaql", None)

        boundary_update_payload = {}
        if name is not None:
            boundary_update_payload["name"] = name

        if affected_sites is not None:
            if isinstance(affected_sites, list):
                self.log.debug(
                    "affected_types was list, converting to a comma-delimited str",
                )
                # check if there is a comma in the name
                # we can't update a boundary using an affected site with a comma in it
                for affected_site in affected_sites:
                    if "," in affected_site:
                        raise ValueError(
                            "Site '"
                            + affected_site
                            + "' contains a comma - Armis API doesn't support this",
                        )
                    boundary_update_payload["affectedSites"] = affected_sites

                affected_sites = ",".join(affected_sites)

            boundary_update_payload["affectedSites"] = affected_sites

            if ruleaql is not None:
                boundary_update_payload["ruleAql"] = ruleaql

        # if not provided, fetch it from the cloud so we can round-trip it
        # back to the cloud
        if (
            "name" not in boundary_update_payload
            or "ruleAql" not in boundary_update_payload
        ):
            boundaryfromcloud = self.get_boundary(boundary_id=boundary_id)
            for key in ["name", "ruleAql"]:
                if key not in boundary_update_payload:
                    self.log.debug('"%s" not in payload, adding it', key)
                    boundary_update_payload[key] = boundaryfromcloud[key]

        self.log.debug("payload is now %s", str(boundary_update_payload))

        # PATCH the boundary
        url = self.TENANT_BASE_URL / "v1" / "boundaries" / str(boundary_id) / "/"
        self.log.debug("url=%s", str(url))
        boundary_update = self._api_http_request(
            method="PATCH",
            url=url,
            json=boundary_update_payload,
        )
        self.log.debug("return text=%s", str(boundary_update.text))
        self.log.debug("status_code=%s", str(boundary_update.status_code))
        if boundary_update.status_code != httpx.codes.OK:
            self.log.info(
                "FAILED boundary update for boundary_id: %s",
                str(boundary_id),
            )
            self.log.debug(boundary_update.text)
            raise Exception("boundary update issue", boundary_update.text)

    def get_devices(self, **kwargs: dict) -> list:
        """Get devices from inventory matching ASQ.

        Parameters
        ----------
        asq : str
            ASQ to execute.
        fields_wanted : list
            List of fields wanted.

        Returns
        -------
        inventory: list
            Inventory items matching ASQ.
        """
        get_devices_start = pendulum.now()
        asq = kwargs.get("asq", None)
        if asq is None:
            raise ValueError("no asq provided")
        self.log.info("asq=%s", asq)

        fields_wanted = kwargs.get("fields_wanted", [])
        self.log.info("fields_wanted=%s", str(",".join(fields_wanted)))

        url = self.TENANT_BASE_URL / "v1" / "devices/"
        url.args["search"] = asq
        url.args["from"] = 0
        url.args["length"] = self.ARMIS_API_PAGE_SIZE

        # NOTE:
        # From the API Guide v1.8:
        # Iterating over a set of results it is recommended best practice to
        # orderBy a fixed parameter (deviceId for example) in order to not to
        # miss data between pages. This is because the default order is by
        # lastSeen, so results can change.
        url.args["orderBy"] = "id"

        inventory = []
        inventory_total = self.get_devices_count(asq=asq)
        self.log.debug("inventory_total=%s", str(inventory_total))

        if inventory_total == 0:
            return []

        remaining_time = -1
        filenames = []
        filenumber = 1

        while url.args["from"] is not None:
            page_fetch_start = pendulum.now()
            self.log.info(
                "fetching %s - %s of a total of %s",
                str(url.args["from"]),
                str(url.args["from"] + self.ARMIS_API_PAGE_SIZE),
                str(inventory_total),
            )
            device_details = self._api_http_request(method="GET", url=url)

            if device_details.status_code != httpx.codes.OK:  # pragma: no cover
                self.log.critical("STATUS CODE != 200")  # pragma: no cover
                self.log.critical(
                    "status_code=%s",
                    str(device_details.status_code),
                )  # pragma: no cover
                self.log.critical("text=%s", device_details.text)  # pragma: no cover
                self.log.critical("continuing")  # pragma: no cover
                continue  # pragma: no cover

            devices = self._json_decoder.decode(device_details.text)

            if len(devices["data"]["data"]) > 0:
                fetchedcolumns = list(devices["data"]["data"][0].keys())
                self.log.debug("Fetched columns=%s", str(fetchedcolumns))
                setdiff = set(fields_wanted).difference(fetchedcolumns)
                if len(setdiff) > 0:
                    self.log.info(
                        "Fields missing from wanted columns=%s",
                        ",".join(list(setdiff)),
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
                self.log.debug(
                    "can't find fields, return from this iteration=%s",
                    str(devices),
                )  # pragma: no cover
                return []  # pragma: no cover

            now = pendulum.now()
            filename = pl.Path(
                str(self.temporary_directory.name)
                + "/"
                + f"devices_{now.float_timestamp}.json.gz",
            )

            self.log.info("devices filename=%s", str(filename))
            # using default zlib compression level (i.e. -1 AKA 6)
            filename.write_bytes(gzip.compress(device_details.content))
            filenames.append(filename)
            filenumber += 1

            now = pendulum.now()
            self.log.debug("now=%s", str(now))
            self.log.debug("get_devices_start=%s", str(get_devices_start))

            total_elapsed_time = now.timestamp() - get_devices_start.timestamp()
            self.log.debug("total_elapsed_time=%s", str(total_elapsed_time))

            page_fetch_time = now.timestamp() - page_fetch_start.timestamp()
            self.log.info("page fetch time=%s", str(page_fetch_time))

            # if the page_fetch_time exceeds 90% of the http timeout,
            # start reducing the size of our pages so we can fit the page request
            # into the http timeout period.
            if page_fetch_time > self._http_timeout * 0.9:
                self.ARMIS_API_PAGE_SIZE = self._ceiling_up(
                    self.ARMIS_API_PAGE_SIZE * 0.90,
                    100,
                )  # pragma: no cover
                url.args["length"] = self.ARMIS_API_PAGE_SIZE  # pragma: no cover

                self.log.info(
                    r"page_fetch_time > %s, reducing page size by 10%% to %s",
                    str(int(self._http_timeout * 0.9)),
                    str(self.ARMIS_API_PAGE_SIZE),
                )  # pragma: no cover

            if url.args["from"] > 0:
                time_per_device = (
                    total_elapsed_time / url.args["from"]
                )  # pragma: no cover
                self.log.debug(
                    "time_per_device=%s",
                    str(time_per_device),
                )  # pragma: no cover

                remaining_devices = (
                    inventory_total - url.args["from"]
                )  # pragma: no cover
                self.log.debug(
                    "remaining_devices=%s",
                    str(remaining_devices),
                )  # pragma: no cover

                remaining_time = remaining_devices * time_per_device  # pragma: no cover
                self.log.debug(
                    "remaining_time=%s",
                    str(remaining_time),
                )  # pragma: no cover

            if remaining_time < 0:
                estimated_end_time = now
            else:
                estimated_end_time = now.add(seconds=remaining_time)  # pragma: no cover

            self.log.info("estimated_end_time=%s", str(estimated_end_time))

            url.args["from"] = devices["data"]["next"]

        # reproduce inventory here
        for filename in filenames:
            self.log.info("reading %s", str(filename.name))
            j = self._json_decoder.decode(gzip.decompress(filename.read_bytes()))
            self.log.info("appending %s records", str(len(j["data"]["data"])))
            inventory.extend(j["data"]["data"])

        self.log.debug("inventory size=%s", str(len(inventory)))

        return inventory

    def get_devices_count(self, **kwargs: dict) -> int:
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
        asq = kwargs.get("asq", None)

        if asq is None:
            raise ValueError("asq is required")
        self.log.info("asq=%s", asq)

        url = self.TENANT_BASE_URL / "v1" / "devices/"
        url.args["search"] = asq
        url.args["length"] = 1
        url.args["from"] = 0
        url.args["fields"] = "id"
        self.log.debug("url=%s", str(url))

        inventory_total_request = self._api_http_request(method="GET", url=url)
        if inventory_total_request.status_code != httpx.codes.OK:
            raise Exception(
                "inventory issue",
                inventory_total_request.text,
            )  # pragma: no cover

        inventory_total = int(
            self._json_decoder.decode(inventory_total_request.text)["data"]["total"],
        )
        self.log.info("inventory_total=%s", str(inventory_total))
        return inventory_total

    def tag_device(self, **kwargs: dict) -> None:
        """Add or remove a device from a deviceid.

        Parameters
        ----------
        device_id : int
            Device ID to tag.
        tags: list|str
            Tags to add to or remove from the device ID.
        action: {'add', 'remove'}
            Action to perform, one of add or remove.
        """
        self.log.debug("tag_device")
        device_id = kwargs.get("device_id", None)
        if device_id is None:
            raise ValueError("no device_id specified")

        self.log.debug("device_id=%s", str(device_id))

        tags = kwargs.get("tags", [])
        self.log.debug("tags type=%s", str(type(tags)))

        if isinstance(tags, str):
            self.log.debug("type was string, converting to list")
            tags = [tags]

        self.log.debug("tags=[%s]", str(",".join(tags)))
        action: str = kwargs.get("action", "add")
        action = str(action).lower()
        self.log.debug("action=%s", str(action))

        if len(tags) == 0:
            raise ValueError("no tag provided")

        if action not in {"add", "remove"}:
            raise ValueError("no valid action provided, should be one of add or remove")

        url = self.TENANT_BASE_URL / "v1" / "devices" / str(device_id) / "tags/"
        self.log.debug("url=%s", str(url))

        tag_payload = {"tags": tags}
        self.log.debug("json currently=%s", str(tag_payload))
        self.log.info(
            "tagging, action=%s, deviceid=%s, tags=%s",
            action,
            device_id,
            str(",".join(tags)),
        )

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

        self.log.debug("return text=%s", str(tag_device_update.text))
        self.log.debug("status_code=%s", str(tag_device_update.status_code))
        if tag_device_update.status_code != httpx.codes.OK:
            self.log.info("FAILED DEVICE TAG for device ID: %s", str(device_id))
            self.log.debug(tag_device_update.text)
            raise Exception("tag_device_update issue", tag_device_update.text)

        return tag_device_update.text

    def get_collector(self, collector_id: int) -> dict:
        """Get a collector given the collector_id.

        Parameters
        ----------
        collector_id : int
            The collector ID to fetch details about.

        Returns
        -------
        collectors_dict : dict
            A dictionary of a collector.
        """
        if collector_id is None:
            raise ValueError("collector_id is required")

        self.log.info("collector_id=%s", str(collector_id))
        url = self.TENANT_BASE_URL / "v1" / "collectors" / "/" / str(collector_id) / "/"
        self.log.debug("url=%s", str(url))
        collector_request = self._api_http_request(method="GET", url=url)
        if collector_request.status_code != httpx.codes.OK:
            raise Exception("collector issue", collector_request.text)

        return self._json_decoder.decode(collector_request.text)["data"]

    def get_collectors(self) -> dict:
        """Get a dictionary of collectors.

        Returns
        -------
        collectors_inventory : dict
            A dictionary of collectors.

        """
        url = self.TENANT_BASE_URL / "v1" / "collectors/"
        url.args["from"] = 0
        url.args["length"] = self.ARMIS_API_PAGE_SIZE
        collectors_inventory = {}

        while url.args["from"] is not None:
            self.log.info(
                "fetching %s-%s",
                str(url.args["from"]),
                str(url.args["from"] + self.ARMIS_API_PAGE_SIZE),
            )
            get_collectors_request = self._api_http_request(method="GET", url=url)
            if get_collectors_request.status_code != httpx.codes.OK:
                self.log.critical("STATUS CODE != 200")
                self.log.critical(
                    "status_code=%s",
                    str(get_collectors_request.status_code),
                )
                self.log.critical("text=%s", get_collectors_request.text)
                self.log.critical("continuing")
                continue

            collectors_response = self._json_decoder.decode(get_collectors_request.text)
            collectors_count = collectors_response["data"]["count"]
            self.log.debug("retrieved %s collectors", str(collectors_count))

            for collector in collectors_response["data"]["collectors"]:
                collectornumber = collector["collectorNumber"]
                collectors_inventory[collectornumber] = collector

            self.log.debug(
                "collectors next=%s",
                str(collectors_response["data"]["next"]),
            )
            url.args["from"] = collectors_response["data"]["next"]

        self.log.debug("collectors_inventory size=%s", str(len(collectors_inventory)))

        if len(collectors_inventory) > 0:
            collectors_inventory = dict(sorted(collectors_inventory.items()))
        return collectors_inventory

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
        Armis Cloud version >= R-24.0.
        """
        if integration_id is None:
            raise ValueError("an integration_id is required")

        url = self.TENANT_BASE_URL / "v2" / "integrations" / str(integration_id)
        url = url / "/"
        url.args = {}

        integration_details = self._api_http_request(method="GET", url=url)

        if integration_details.status_code == httpx.codes.NOT_FOUND:
            self.log.debug("integration was not found")
            self.log.debug("text=%s", integration_details.text)
            return {}

        if integration_details.status_code != httpx.codes.OK:
            self.log.critical("STATUS CODE=%s", integration_details.status_code)
            self.log.debug(
                "status_code=%s",
                str(integration_details.status_code),
            )
            self.log.debug("text=%s", integration_details.text)
            raise Exception("integration_details issue", integration_details.text)

        integration = self._json_decoder.decode(integration_details.text)["data"][0]
        return integration

    def get_integrations(self) -> dict:
        """Get a list of integrations.

        Returns
        -------
        integrations : dict
            a dictionary of integrations

        Notes
        -----
        This method requires v2 of the API call which is only available in the
        Armis Cloud version >= R-24.0.
        """
        url = self.TENANT_BASE_URL / "v2" / "integrations/"
        url.args["from"] = 0
        url.args["length"] = self.ARMIS_API_PAGE_SIZE

        integrations_count = self.get_integrations_count()

        integrations = {}

        while url.args["from"] is not None:
            self.log.info(
                "fetching %s-%s of a total of %s",
                str(url.args["from"]),
                str(url.args["from"] + self.ARMIS_API_PAGE_SIZE),
                str(integrations_count),
            )

            self.log.debug("url=%s", str(url))
            integrations_details = self._api_http_request(method="GET", url=url)

            if integrations_details.status_code != httpx.codes.OK:
                self.log.critical("STATUS CODE != 200")
                self.log.critical(
                    "status_code=%s",
                    str(integrations_details.status_code),
                )
                self.log.critical("text=%s", integrations_details.text)
                raise Exception("integrations_details issue", integrations_details.text)

            for integration in self._json_decoder.decode(integrations_details.text)[
                "data"
            ]["integrations"]:
                integrationid = integration["id"]
                integrations[integrationid] = integration

            url.args["from"] = self._json_decoder.decode(integrations_details.text)[
                "data"
            ]["next"]

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
        Armis Cloud version >= R-24.0.
        """
        url = self.TENANT_BASE_URL / "v2" / "integrations/"
        url.args["length"] = 1
        self.log.debug("url=%s", str(url))
        count_request = self._api_http_request(method="GET", url=url)
        return int(self._json_decoder.decode(count_request.text)["data"]["total"])

    def get_sites(self) -> dict:
        """Get a list of sites.

        Returns
        -------
        sites : dict
            A dict of sites.

        Notes
        -----
        Only applies to cloud version >= R-23.3-S182.
        """
        url = self.TENANT_BASE_URL / "v1/sites/"
        url.args["from"] = 0
        url.args["length"] = self.ARMIS_API_PAGE_SIZE
        url.args["includeTotal"] = "true"

        sites = {}
        while url.args["from"] is not None:
            self.log.debug("url=%s", str(url))
            sites_details = self._api_http_request(method="GET", url=url)

            if sites_details.status_code != httpx.codes.OK:
                self.log.critical("STATUS CODE != 200")
                self.log.critical("status_code=%s", str(sites_details.status_code))
                self.log.critical("text=%s", sites_details.text)

            if "sites" in self._json_decoder.decode(sites_details.text)["data"]:
                for site in self._json_decoder.decode(sites_details.text)["data"][
                    "sites"
                ]:
                    sites[site["id"]] = site

            url.args["from"] = self._json_decoder.decode(sites_details.text)["data"][
                "next"
            ]

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
        site_id = kwargs.get("site_id", None)

        if site_id is None:
            raise ValueError("site_id was not provided")

        url = self.TENANT_BASE_URL / "v1" / "sites" / str(site_id) / "/"
        self.log.debug("url=%s", str(url))

        site_request = self._api_http_request(method="GET", url=url)
        if site_request.status_code != 200:
            self.log.critical("STATUS CODE !=200")
            self.log.critical("status_code=%s", str(site_request.status_code))
            self.log.critical("text=%s", site_request.text)
            self.log.critical("continuing")
            raise Exception("dashboard http response !=200")

        if "data" in self._json_decoder.decode(site_request.text):
            return self._json_decoder.decode(site_request.text)["data"]
        return {}
