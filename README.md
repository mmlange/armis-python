# Armis Python Library

<p align="center"><strong>armis</strong> <em>- A Python library for interacting with the Armis cloud.</em></p>

<p align="center">
<a href="https://github.com/mmlange/armis-python/actions">
    <img src="https://github.com/mmlange/armis-python/actions/workflows/testsuite.yml/badge.svg" alt="Test Suite">
</a>
</p>

**armis** is a Python client library for interacting with the Armis cloud.  It connects using **HTTP/2** by default,
falling back to **HTTP/1.1** when necessary.  Python 3.8+ is supported.

---

Install **armis** using pip:

```console
$ pip install armis
```

# A Quick Demo of Features

## Getting Started
First, let's create an ArmisCloud object:
```python
from armis import ArmisCloud

a = ArmisCloud(
    api_secret_key="your-api-secret-key-here",
    tenant_hostname="your-tenant-hostname-here.armis.com"
)
```

## Device Operations
Let's get a list of all devices matching our ASQ and only retrieve a few fields:

```python
devices = a.get_devices(
    asq='in:devices timeFrame:"10 Seconds"',
    fields=["id", "ipAddress", "name", "firstSeen"]
)
print(devices)

[{"id": 15, "ipAddress": "10.1.2.3", "name": "super-pc", "firstSeen": "2019-05-15T13:00:00+00:00"}]
```

## Boundary Operations

Let's get all of the boundaries known to the system:
```python
boundaries = a.get_boundaries()
print(boundaries)

{1: {'affectedSites': '', 'id': 1, 'name': 'Corporate', 'ruleAql': {'or': ['ipAddress:10.0.0.0/8']}}, 2: {'affectedSites': '', 'id': 2, 'name': 'Guest', 'ruleAql': {'or': ['lastConnectedSsid:Guest']}}}
```

Let's get only one boundary by ID:
```python
boundaryone = a.get_boundary(boundary_id=1)
print(boundaryone)

{"data":{"affectedSites":"","id":1,"name":"Corporate","ruleAql":{"or":["ipAddress:10.0.0.0/8"]}},"success":true}
```

Deleting a boundary is easy:

```python
result = a.delete_boundary(boundary_id=3424234)
print(result)
{"success": True}
```

Creating a boundary is easy, though the syntax is not yet documented well here:
```python
result = a.create_boundary(
    name="My New Boundary",
    ruleaql={ "or": [
        "ipAddress:10.0.0.0/24"
        ]
    }
)
print(result)
{'data': {'id': 392309238}, 'success': True}
```

## Collector Operations
Get a list of collectors:

```python
collectors = a.get_collectors()
print(collectors)

{1234: {'clusterId': 0, 'collectorNumber': 1234, 'defaultGateway': '10.0.0.1', 'httpsProxyRedacted': '', 'ipAddress': '10.0.0.2', 'lastSeen': '2019-05-15T13:00:00+00:00', 'macAddress': '00:12:34:56:78:90', 'name': 'Collector 1234', 'status': 'Offline', 'subnet': '10.0.0.0/24', 'type': 'Physical'}}
```

Get the details for a specific collector:

```python
myimportantcollector = a.get_collector(collector_id=1234)
print(myimportantcollector)

{'clusterId': 0, 'collectorNumber': 1234, 'defaultGateway': '10.0.0.1', 'httpsProxyRedacted': '', 'ipAddress': '10.0.0.2', 'lastSeen': '2019-05-15T13:00:00+00:00', 'macAddress': '00:12:34:56:78:90', 'name': 'Collector 1234', 'status': 'Offline', 'subnet': '10.0.0.0/24', 'type': 'Physical'}
```

## User Operations
Get a list of users:
```python
users = a.get_users()
print(users)

{12: {'email': 'johndoe@example.com', 'id': 12, 'isActive': True, 'lastLoginTime': '2019-05-15T13:01:23.456789', 'location': '', 'name': 'John Doe', 'phone': '', 'povEulaSigningDate': None, 'prodEulaSigningDate': None, 'reportPermissions': None, 'role': None, 'roleAssignment': [{'name': ['Admin']}], 'title': '', 'twoFactorAuthentication': False, 'username': 'johndoe'}}
```

Get the details for a specific user, either by userid or email address:
```python
a_user = a.get_user(12)
{'email': 'johndoe@example.com', 'id': 12, 'isActive': True, 'lastLoginTime': '2019-05-15T13:01:23.456789', 'location': '', 'name': 'John Doe', 'phone': '', 'povEulaSigningDate': None, 'prodEulaSigningDate': None, 'reportPermissions': None, 'role': None, 'roleAssignment': [{'name': ['Admin']}], 'title': '', 'twoFactorAuthentication': False, 'username': 'johndoe'}

a_user = a.get_user('johndoe@example.com')
{'email': 'johndoe@example.com', 'id': 12, 'isActive': True, 'lastLoginTime': '2019-05-15T13:01:23.456789', 'location': '', 'name': 'John Doe', 'phone': '', 'povEulaSigningDate': None, 'prodEulaSigningDate': None, 'reportPermissions': None, 'role': None, 'roleAssignment': [{'name': ['Admin']}], 'title': '', 'twoFactorAuthentication': False, 'username': 'johndoe'}
```

Delete a user by user_id or email address:
```python
a.delete_user('12')
```

## Features

**armis** gives you:

* Easy connection to the Armis cloud using an API secret key.
* A quick way to fetch devices from the cloud.
* Retries in the event the cloud times out.  This can happen with large queries that take more than 2 minutes.  This is the default for CloudFlare, which front-ends the cloud infrastructure.
* Mostly type annotated.
* Nearly 100% test coverage.


## Installation

Install with pip:

```console
$ pip install armis
```

**armis** requires Python 3.8+.

## Dependencies
**armis** relies on these excellent libraries:
* [furl](https://github.com/gruns/furl) - provides easy-to-use URL parsing and updating
* [httpx](https://github.com/encode/httpx/) - The underlying transport implementation for making HTTP requests
* [msgspec](https://github.com/jcrist/msgspec) - for lightning fast decoding of JSON
* [pendulum](https://github.com/sdispater/pendulum) - for easy date/time management
* [tenacity](https://github.com/jd/tenacity) - retry management when things fail, with great retry/backoff options

## License
`armis` is distributed under the terms of the [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) license.
