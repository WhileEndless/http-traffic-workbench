# HTTP Traffic Workbench

**v1.0.0** · [GitHub releases](https://github.com/WhileEndless/http-traffic-workbench/releases) · [WhileEndless](https://github.com/WhileEndless)

HTTP Traffic Workbench is a Burp Suite extension built on the Montoya API for passive HTTP traffic search and session analysis. Follow identifiers across requests, responses, field names, and formats, and label related records in Proxy history.

## What it does

- **Find where a value appears.** An identifier submitted as a form field can also appear under a different name in JSON, an XML element, an HTML input, a JavaScript assignment, or an HTTP header. Search also reads query parameters, cookies, and JSON embedded in HTML or mislabeled as another content type.
- **Follow the relationship between a field and its value.** Select a field name or value in a Burp message and start an **Auto** search. The extension uses the selected message for context and searches for alternate field names through exact value matches. **Related fields** can surface comparable identifiers, such as two values with the same prefix and numeric width. Direct matches score higher.
- **Search the sources you select.** Use Proxy history, Target Site Map, Scanner issue evidence, supported Organizer items, and imported traffic. Enable capture to include new traffic from tools such as Scanner, Repeater, Intruder, and extensions. Older Logger traffic can be added from selected messages or a Logger CSV export.
- **Track users by session.** Select a login exchange, choose where to read the user identifier, and pick the session cookie. Preview which Proxy history records would receive the user label. Save the rule to the project or export it for another project. Search also works without user labels.

## Install

1. Download `http-traffic-workbench.jar` from the [v1.0.0 release](https://github.com/WhileEndless/http-traffic-workbench/releases/tag/v1.0.0).
2. In Burp Suite 2025.5 or later, open **Extensions → Installed → Add**.
3. Choose **Java**, select the JAR, and click **Next** to load it. Open the **HTTP Traffic Workbench** tab.

To verify the download, compare its SHA-256 digest with `http-traffic-workbench.jar.sha256` from the same release.

## Build from source

Use JDK 17 or later and Maven. The build runs the tests and writes the extension to `target/http-traffic-workbench.jar`.

```sh
mvn clean package
```

## Try it

1. Open the [fictional demo archive](examples/demo-traffic.tsv) on GitHub and choose **Download raw file**. In the extension, select **Import archive** and open the downloaded TSV.
2. Open **Search all traffic**, enable **Extension archive** and **Repeater** under **Sources**, and search for `demo-user-42` in **Auto** mode.
3. Inspect **Direct matches** to see fields such as `username`, `userId`, and `accountRef`. Switch to **Related fields** to see the comparable identifier `demo-user-84`. Click a result to inspect the request and response. Results appear while the scan runs.

To use your own traffic, select text in a Burp message and choose **HTTP Traffic Workbench · Search traffic for selection** from the context menu. For user labels, right-click a login in **Proxy → HTTP history** and choose **HTTP Traffic Workbench · Use selected exchange as login**.

## Documentation

- [Offline demo and expected results](examples/README.md)
- [User guide](docs/user-guide.md) covers search modes and scoring, traffic sources, supported formats, cookie tracing, user labeling, project transfer, and performance limits.
- [Release notes](CHANGELOG.md)
