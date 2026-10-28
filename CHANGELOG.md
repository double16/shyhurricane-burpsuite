ShyHurricane-BurpSuite Changelog
================================

1.4.0
----------

## Features

- Add structured finding metadata, per-request finding targets, background automatic
  finding delivery, and bounded transient retries for findings submissions.

## Fixes

- Cancel active findings connections on unload and preserve identical payloads
  across transient retries.

1.3.0
----------

## Features

- Add **Send** to ShyHurricane's issue and HTTP message context menus, supporting
  multiple selections and bypassing all automatic forwarding filters.

1.2.0
-----

- Add ability to filter by status codes.
- Update the Gradle to 9.8.0 and other dependency upgrades.

1.1.0
-----

- Add ability to filter by sources (Proxy, Repeater, ...).

1.0.0
-----

- Initial Release
