# HTTP Traffic Workbench user guide

[Overview and quick start](../README.md) · [Offline walkthrough](../examples/README.md)

A Burp Suite extension for cross-format search, tool traffic, and user labeling. Search Proxy history, project data, and the extension's optional traffic archive. Extract a user identifier from a request or response and use a session cookie to label related traffic.

## Install

1. Download `http-traffic-workbench.jar` from [GitHub Releases](https://github.com/WhileEndless/http-traffic-workbench/releases).
2. In Burp Suite 2025.5 or later, open **Extensions → Installed → Add**, select **Java**, choose the JAR, and click **Next**.
3. Open the **HTTP Traffic Workbench** tab. **Info** shows the release and GitHub links. Burp’s extension output logs them at startup.

Build from source with JDK 17 or later and Maven. Run `mvn clean package` to run the tests and build `target/http-traffic-workbench.jar`. The JAR bundles its JSON parser and loads the Montoya API from Burp. Info and the JAR manifest show the installed version.

[PortSwigger · Loading an extension in Burp](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/loading-in-burp)

### Troubleshooting

- If the extension fails to load, select it under **Extensions → Installed** and check its **Errors** tab. Confirm that Burp is version 2025.5 or later and that the selected file is `http-traffic-workbench.jar`.
- If the offline demo returns no results, select both **Extension archive** and **Repeater** under **Sources** and reset the advanced filters. If **Same host** is using a selection from another service, clear it for the demo.
- If the archive import fails, use the raw demo TSV or a supported Logger CSV. A Logger CSV needs the raw HTTP request and a URL or host column.

## Search traffic

1. Select **Search all traffic** or **Search archive**. You can also select text in a Burp HTTP editor, right-click, and select **HTTP Traffic Workbench · Search traffic for selection**.
2. Enter a term and press **Enter** or click **Search**. Use **Browse traffic** to list records with an empty query. Opening search with no text selection leaves the query empty. **Auto** searches field names, values, and plain text. The message selection provides field context when available.
3. Direct matches and comparable values from fields identified by the selected message appear as the scan runs. The status shows how many records have been read. Links that need evidence from other records can appear later. If a value matches on both sides, the request and response each get a row. Selecting a row opens the exchange and highlights its own side. **Value** preserves the original spelling of URL-encoded form values. Select **Load full response** for oversized responses. The message editor search bars use the original spelling of matched form names and values, including percent escapes. **All matches** shows direct results first and related results below. Use **Direct matches** or **Related fields** to focus the view. **Copy page** copies the visible page. **Stop** keeps the matches already shown.

**Depth** defaults to **1**. In **Auto**, selecting a key in a structured message searches for the key both as a field name and as a literal value. Its paired value can then lead to other fields, even when the source message is outside the selected traffic sources. Selecting the value does the reverse. For example, from `customerRef=demo-7428`, Auto can find `targetField=customerRef` and a response field `reference` containing `demo-7428`.

An HTML control searched by `name` or its explicit `id` can lead to other fields through its `value`, including URL-encoded equivalents and cross-format matches. When searching by value, the submitted `name` identifies the field. An ID-only control can corroborate an exact key match in another structured message. **Depth 2–3** can follow comparable values through an established field to further exact matches.

**Auto**, **Field name**, and **Field value** compare literal terms first and recognize one layer of URL percent encoding or HTML character references. For example, `17/08/2018`, `17%2F08%2F2018`, and `17&#47;08&#47;2018` can match the same field. The comparison also works when a field contains the encoded spelling. A selected form exchange can supply its declared charset when the decoded term matches one of its fields. **Auto** can also match encoded text when no structured match is available. **Text** keeps the entered spelling for literal and regex searches.

An exact value match can teach the search another field or header name. For example, `demo-7428` can lead from `userId` to `X-Account-ID` and reveal `demo-9988` under that header. After establishing a field name from an exact match or the selected message, search checks matching body fields across URLs and formats. Valid calendar dates under that name can use different years, separators, and day, month, or year order. Other comparable values can share a digit width, a code prefix with the same numeric suffix width, or a UUID format. Search keeps comparable values in a separate bounded index while scanning. Only when that index fills does search revisit the chosen traffic for comparable values under the established names. Logging and metadata fields can teach the search their names. A comparable value from one of these fields needs an exact match in a separate field outside that category to appear as related. Name searches include fields with no value. Related-field discovery skips blank values and counters such as `1/1`. A reference to a literal field name is shown as a link and does not by itself extend the search. Cookie and common credential header values are masked in structured results. Use **0** for direct results, or **2–3** to pursue more links through exact shared values.

The highest scores go to exact field-and-value matches. Standalone exact values and partial matches follow. Related variants rank below direct hits, with selected fields ranked above inferred aliases.

**Mode** can focus the scan on **Field name**, **Field value**, or **Text**. HTTP header names are case-insensitive. Body field names, cookie names, and exact structured values are case-sensitive. Text search is case-insensitive by default. **Advanced** includes URL, message direction, Burp scope, HTTP method, status or status family, MIME type, file extension, listener port, response presence, parameters, and annotations. Select **Regex** or **Exclude matches** for text search. Separate exchanges appear separately. Enable **Collapse repeated matches** to keep one example per user, endpoint, tool, and message side. In that view, a complete exchange replaces an earlier request-only example. Results work with or without user labels and can include requests without responses.

### Traffic sources

Use **Sources** to switch individual sources on or off. The menu has **All** and **None** actions. When results are open, changing sources refreshes the search once after the menu closes. The **Tool** column identifies the origin and **Side** shows whether the match was in the request or response.

**Same host** is checked by default in the main search controls. It uses the hostname of the HTTP message that opened the search and includes that host across paths, ports, and protocols. In a search opened from the suite tab, select a result to choose the host for the next search. Clear **Same host** to search across hosts.

When you open the search from an HTTP message's context menu, the selected exchange is searched too. It follows the chosen sources and filters and does not need to have been captured or archived.

| Source | Availability |
| --- | --- |
| **Proxy history** | Existing browser and client traffic in Proxy HTTP history, including records without responses. |
| **Target site map** | Request and response samples retained in the current Site map. |
| **Scanner findings** | HTTP evidence attached to issues in the Site map. |
| **Organizer** | Existing items on Burp versions that expose Organizer reads through Montoya. |
| **Scanner, Repeater, Intruder, Extensions, Sequencer, Session handling and replay, Burp AI, Other Burp tools** | New HTTP traffic from each enabled tool and imported records with that tool attribution. |
| **Extension archive** | Archived Proxy samples, older archive formats, and manually imported or selected messages without a specific tool attribution. |

**Search archive** starts with the extension archive and captured or imported tool traffic selected. Where older tool traffic is available as a selected message, such as in Logger or Repeater, **Archive this exchange** and **Archive selected exchanges** add full HTTP messages for future searches. Proxy history and Target site-map messages can be searched directly.

To record future tool traffic, open **Project settings → Capture tools**, select the tools, and save the profile. Capture uses the configured target scope, host list, path filter, and optional 2xx/3xx condition. Tool capture is passive and starts when enabled. Requests without a response remain browseable when the 2xx/3xx condition is off.

Burp's **Logger** is the place to inspect older traffic from every tool. The public Montoya API supports live HTTP observation and selected or exported Logger records. For earlier Logger records, right-click and archive the exchanges, or export Logger CSV and use **Import archive**. The CSV must include raw HTTP in **Request** and the **URL** or **Host** column. Include **Response** and **Tool** to keep the response and attribution. Burp attributes extension-generated requests to Extensions and modifications to the originating tool. [Burp Logger](https://portswigger.net/burp/documentation/desktop/tools/logger) · [Logger CSV export](https://portswigger.net/burp/documentation/desktop/tools/logger/entries) · [Extension traffic attribution](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/viewing-requests-sent-by-burp-extensions) · [Montoya HTTP handler](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/Http.html)

### Supported formats

- **JSON** includes nested objects, arrays, and JSON encoded inside strings. A valid JSON body is recognized even when a server reports `text/html` or another type. Search also examines loose JSON and recognizable inline fragments.
- **XML and SOAP** support local element names, attributes, and leaf text. Parsing uses local input with DTD and external entity resolution disabled.
- **Forms and queries** include URL-encoded parameters, multipart text fields, nested multipart parts, and structured values embedded in forms. Search also recognizes URL-encoded form data carried in a JSON string or XML text field.
- **HTML** includes input and output controls, textareas, select options, meta fields, and `data-*` attributes. HTML control IDs are searchable directly. A submitted name provides the field context on a value match. An explicitly searched ID can also lead to related values. Structured JSON fields are also extracted from script blocks, quoted attributes, and visible text such as a `pre` block. Embedded scanning uses a separate 1 MiB text budget per message.
- **JavaScript** includes static literals in script responses, inline scripts, and event attributes. Dynamic expressions are searchable as source text. Script files become searchable when they appear in Proxy history.
- **Plain text** includes HTTP headers, request paths, queries, and decoded bodies. Auto also recognizes simple `name=value` and `name: value` lines. The extension supports gzip, deflate, and declared body character sets. Formats without a field parser, including opaque binary bodies, use text search over the available body text.

## Trace a cookie

Right-click an HTTP exchange and select **HTTP Traffic Workbench · Trace a cookie**. Choose an observed cookie from the request or response, or open **Trace a cookie** from the main tab and enter a name and value manually. The input masks the value, and the cookie value column displays `Hidden` in the table and copied rows. The trace itself keeps the value in memory for the search. The original HTTP message in the preview, or in an exported HTTP archive, can contain the value.

- **Exact trace** searches the case-sensitive cookie name and exact wire value in request `Cookie` and response `Set-Cookie` headers. It uses the sources and direction you select. A trace started from a message defaults to that host, port, and protocol.
- **Follow observed replacements** uses chronological Proxy history for the selected service. A replacement is followed only when one exchange sends the current value and sets one unambiguous replacement. A removal or expiry ends the trace. HTTP filters and direction control what you see while the trace can still use a filtered-out exchange to follow a replacement. The trace starts at the first observed occurrence of the selected value.
- **Use selected exchange as login** is the workflow for writing user labels. It extracts the user ID from the chosen message side and associates it with the cookie. Preview lets you review the proposed notes before writing them.

A cookie name can appear more than once in a message when server paths or domains overlap. Search shows matching header observations. Session labeling uses a single unambiguous value per request and a single unambiguous update from the response. Cookie tracking is passive and scoped to observed HTTP exchanges. [HTTP State Management Mechanism](https://www.rfc-editor.org/info/rfc6265/)

## Label Proxy history

1. Right-click a login exchange in **Proxy → HTTP history** and choose **HTTP Traffic Workbench · Use selected exchange as login**. The wizard opens that request and response and fills in the host, method, and login path.
2. Choose **User identifier source**. The **User identifier field** list follows your Request or Response choice. The wizard shows the value it would use. If you select a field or value in a message before right-clicking, the wizard uses the selection to suggest the source and field.
3. Choose a **Session cookie name**. The wizard shows whether the cookie was sent with the request, set by the response, or both. Optionally enter a **Logout path** such as `/logout`. Use **Logout HTTP method** to match a method such as `POST`. **Logout HTTP status** defaults to `2xx, 3xx` for new rules and also accepts specific codes such as `204, 302`.
4. Select **Preview**. **Preview only the selected session** starts at the exact login and follows its cookie. Clear it to preview every login that matches the route. When identical history rows cannot be distinguished, preview by route is available as an explicit choice.
5. Review the proposed notes, then select **Apply notes**. Existing labels stay in place, including labels that differ from the rule. If individual writes fail, **Apply notes** remains available for retry. Select **Save rule to project** to reuse the route and extraction settings. Enable **Label new Proxy records automatically** to apply them to future traffic.

Search reads these notes into the **User** column. It checks the configured **Note prefix** first, then the saved identifier field or header name. For example, a saved field named `memberReference` allows search to read an existing `memberReference:` note. Save the rule and run the search again to read those notes. With the default `User` prefix, search also recognizes existing `User Code:` and `UserCode:` notes.

Later requests inherit the login's identifier when the host, port, protocol, and cookie match. To establish a session, the login response must have a 2xx or 3xx status, and the exchange must provide one identifier and an unambiguous active cookie. When response timing is available, history waits for that response to complete before using its session. Overlapping exchanges that would assign the same cookie inconsistently can leave it unlabeled until a later login. History skips rows without a timestamp.

A confirmed logout ends the association, even when the next request sends the same cookie. The logout exchange keeps the current label when the session can be identified. A new login can associate that cookie with a user again. Explicit removal, cookie expiry and the idle timeout also end the association. The default idle timeout is 30 minutes.

When login and logout share a route, set **Login request body regex** under **Project settings → User identifier** and **Logout request body regex** under **Project settings → Logout** to distinguish the operations. Add a **Logout response body regex** when the application also returns HTTP 200 for failed logout attempts. These logout conditions must match in addition to the route, method, and status. Enter `any` to skip the HTTP status check. Imported path-only rules keep their previous behavior with `any`. Re-running a rule skips rows with an existing note under the same prefix.

## Try it with anonymous traffic

The offline walkthrough covers cross-format searches, related identifiers, and an exact cookie trace using seven fictional HTTP exchanges. It also explains how to apply the same session setup to a login already present in Proxy history.

[Offline walkthrough](../examples/README.md)

## Configure and transfer a project

- **Capture and storage** control scope, hosts, request path, and the optional HTTP 2xx/3xx filter. Automatic archiving and user notes start disabled.
- **User identifier** settings control request or response priority, field name, HTTP header, or body regex, note prefix, and optional extraction path and HTTP method. A body regex uses its first capture group. Use **Test with body** to check a field name or regex against a sample.
- **Session matching** uses the cookie name and optional end path and idle timeout. Leave the cookie name blank to label each message independently.
- **Save to project** stores the profile in the open Burp project. **Save archive to Burp project** also persists archived request and response samples. Disk persistence for a temporary project depends on saving a Burp project file.
- **Export profile** and **Import profile** transfer settings across projects. Use **Export archive** and **Import archive** separately for traffic samples. Source tags travel with the archive. The TSV archive contains Base64-encoded raw HTTP messages. Previous archive formats can be imported.

Keep Burp projects, Logger exports, traffic screenshots, and project profiles outside the source tree or in the Git-ignored `local-data/` directory. Use synthetic messages and reserved `.test` hosts for examples and test fixtures.

[PortSwigger · Montoya project persistence](https://portswigger.net/burp-but-yours/advanced-concepts/extensions/)

## Performance and limits

Search, cookie tracing, and historical labeling share a low-priority, bounded background queue. Exact searches and cookie traces process records incrementally. Replacement tracking orders the scoped Proxy records before following changes. Cookie tracing reads HTTP headers without decoding message bodies. Result batches update one page at a time. Capture uses a separate bounded queue and archive writes are batched.

- Search reads up to **4 MiB** of decoded body per message. Live Proxy notes use up to **256 KiB**. Messages up to **2 MiB** open automatically and larger messages can be loaded on demand. Automatic editor highlighting applies to messages up to **1 MiB** per side. A truncated structured body may yield fewer fields.
- Results use pages of **200** rows with up to **50,000** matches per search. Discovery has a separate index budget. Direct matching continues when the discovery budget runs out.
- Historical labeling can plan up to **25,000** new notes in one pass. Apply them before running another preview for the remaining records.
- The archive holds up to **2,000** samples or **32 MiB** of raw traffic. It retains up to ten distinct samples per user, service, and endpoint. A single sample can use up to **2 MiB**.
- The session matcher holds up to **2,000** active mappings in memory. The live mapping is rebuilt after reloading the extension.

## Verify

Run `mvn test` for parser, search, streaming, history labeling, transfer, and archive UI tests. Automated tests cover passive multi-tool capture, source filters, Logger imports, score colors, and selection-driven editor search. Synthetic benchmarks report elapsed time and worker CPU time for mixed-format search and historical label replay. Results depend on the source size, message formats, selected filters, and discovery depth.
