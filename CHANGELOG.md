# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.22] - 2024-05-25

### Added

- create_integration, delete_integration, and get_search methods.

### Fixed

- Updated exceptions to be a least a little less generic.

## [1.0.21] - 2024-04-25

### Added

- delete_user, edit_user, get_user, and get_users methods.

### Changed

- Log the first 2,000 characters of return text in debug mode.


## [1.0.20] - 2024-04-24

### Changed

- Updates to method documentation to note dependencies on specific Armis cloud versions.

## [1.0.19] - 2024-04-24

### Added

- _httpx_callback_request_raise_4xx_5xx method to be used as a callback method to the httpx.Client contructor.  If we get a 401 from the cloud, this allows us to fetch another authorization token and raise the issue to tenacity to retry.
- create_boundary and delete_boundary methods.

### Changed

- Begin changes to use the status codes exposed under httpx.codes (e.g. httpx.codes.OK).

## [1.0.18] - 2024-04-23

### Added

- get_sites and get_site methods.

### Removed

- get_boundaries_count method.

## [1.0.17] - 2024-04-23

### Added

- Initial release to the world.
