# shyhurricane-burpsuite

ShyHurricane Forwarder is a Burp Suite extension that forwards HTTP traffic and scanner findings to a [ShyHurricane](https://github.com/double16/shyhurricane) server.

## Configuration

- Server URL
- only-in-scope toggle
- minimum issue severity/confidence
- tool-source filtering
- Automatic HTTP status filtering: 2xx (default), 3xx, 4xx, and 5xx; 1xx is excluded from automatic forwarding

- Automatic forwarding skips non-textual/binary content by inspecting `Content-Type` (e.g., audio/video/font/binary, most images except SVG, `application/octet-stream`, `pdf`, `zip`, `x-protobuf`, etc.).

## How to use it

Building and running tests requires JDK 17 or newer. Set `JAVA_HOME` to that JDK
before running Gradle.
Run the tests with `./gradlew test`.
Run `./gradlew spotlessApply build` to format Java sources, run tests, and verify
at least 80% line and branch coverage per production source file. Coverage reports
are generated in `build/reports/jacoco/test/html/index.html`.

1. Download JAR file from https://github.com/double16/shyhurricane-burpsuite/releases OR
    ```shell
    git clone https://github.com/double16/shyhurricane-burpsuite.git
    cd shyhurricane-burpsuite
    ./gradlew shadowJar
    ls build/libs
    build/libs/ShyHurricaneForwarder-1.1-SNAPSHOT.jar
    ```
2. Load into Burp Suite
   - Burp → Extender → Extensions → Add → Select the JAR.
   - Confirm the extension appears and the `ShyHurricane` tab is visible.
3. Configure in the ShyHurricane tab
   - Server URL: set the ShyHurricane (MCP) server base URL (default `http://localhost:8000`). The extension will call `POST /index` and `POST /findings` on this base.
   - Only in scope: enable to forward only in scope traffic or issues for an in-scope request.
   - Minimum Severity and Confidence
   - Tool sources: either keep “All tools” enabled or uncheck it and select specific tools that should be forwarded.
   - Status codes: select the classes to forward automatically, or click “Select all statuses” to check 2xx–5xx. Only 2xx is selected by default; 1xx is never forwarded automatically. Selecting no classes disables automatic HTTP traffic forwarding. These settings persist and do not affect scanner findings or manual sends.
   - Save/apply your settings.
4. Generate data
   - Use Burp Proxy/Repeater/Scanner as usual. The extension will:
     - Post eligible HTTP traffic to `{server}/index` after responses arrive.
     - Post eligible scanner issues to `{server}/findings` when they’re reported.
5. Verify
   - Check your ShyHurricane server logs/UI for received entries.
   - Watch Burp’s extension output for posting errors if there are connectivity or server-side errors.

## Send selected items manually

Select one or more issues or HTTP messages, right-click, and choose
**ShyHurricane → Send** in Burp's extension context menu. In a request/response
editor, the action sends the current complete message, regardless of highlighted
text. Issue selections send findings; HTTP message selections send request/response
pairs. Issues take precedence if a context supplies both kinds of selection.

Manual sends bypass all forwarding filters: scope, tool source, HTTP status,
content type (including binary content), severity, and confidence. Requests without
responses are skipped; issues without response evidence can still be sent.
Existing body serialization and the 1,024-character limit for each issue evidence
body still apply. You can send the same item again, even if it was already
forwarded automatically.

Sending runs in the background. Burp output reports sent, skipped, failed, and
dropped counts for each selection. A failed selection also reports its first
failure: the HTTP status, a network/configuration hint, or an exception type and
code location. Issue contents, server response bodies, and exception messages are
not logged. If sends fail, check the configured server URL and server availability.
JSON requests use `Content-Type: application/json; charset=UTF-8`; the server must
accept that media type with its charset parameter.
At most 256 items wait in the manual send queue; when it
fills, the oldest pending item is dropped. Unloading discards pending sends and
interrupts the worker. Network operations use 5-second connection and 15-second
read timeouts.
