# shyhurricane-burpsuite

ShyHurricane Forwarder is a Burp Suite extension that forwards HTTP traffic and scanner findings to a [ShyHurricane](https://github.com/double16/shyhurricane) server.

## Configuration

- Server URL
- only-in-scope toggle
- minimum issue severity/confidence
- tool-source filtering
- HTTP status filtering: 2xx (default), 3xx, 4xx, and 5xx; 1xx is always excluded

- Skips non-textual/binary content by inspecting `Content-Type` (e.g., audio/video/font/binary, most images except SVG, `application/octet-stream`, `pdf`, `zip`, `x-protobuf`, etc.).

## How to use it

Building and running tests requires JDK 17 or newer. Set `JAVA_HOME` to that JDK
before running Gradle.
Run the tests with `./gradlew test`.

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
   - Status codes: select the classes to forward, or click “Select all statuses” to check 2xx–5xx. Only 2xx is selected by default; 1xx is never forwarded. Selecting no classes disables HTTP traffic forwarding. These settings persist and do not affect scanner findings.
   - Save/apply your settings.
4. Generate data
   - Use Burp Proxy/Repeater/Scanner as usual. The extension will:
     - Post eligible HTTP traffic to `{server}/index` after responses arrive.
     - Post eligible scanner issues to `{server}/findings` when they’re reported.
5. Verify
   - Check your ShyHurricane server logs/UI for received entries.
   - Watch Burp’s Extender output for messages like `Failed to POST ...: HTTP <status>` if there are connectivity or server-side errors.
