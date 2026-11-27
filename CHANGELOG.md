# Release notes

## 1.2.0

- Add a searchable **Users** tab for labels observed in Proxy history and saved traffic. Select a label to browse its records or use **User filter** in search.
- Search for compatible JSON fields across requests and responses. Follow exact matches through other fields at up to three levels, the new default.
- Follow learned field names across JSON, HTML, static JavaScript, XML, and forms, including links between decimal integers and their text spellings.
- With **Partial value matches** enabled, find discovered values inside longer fields at token boundaries.
- Match quoted and unquoted decimal integer values in JSON. Continue checking related JSON fields when the discovery index fills.
- Leave **Target site map** off by default. Enable it in **Sources** when needed.
- Open responses up to 6 MiB automatically and load larger responses on demand.
- Read user labels alongside other lines in Proxy notes. The Users view shows labels and record counts and reads the current project locally.

## 1.1.0

- Highlight the originating user in the **User** column when searching from a labeled HTTP message. The highlight applies to matching user labels on the same host.
- Add **Hide source user** to the search results. It filters displayed and incoming matches during a search. Clear the checkbox to restore hidden rows without running the search again.

## 1.0.2

- Fix selection-based searches in formatted HTTP editors by reading the selected text directly and preserving line breaks in the search term.
- Show user labels from existing Proxy history notes that use the saved identifier field or header name. Prefer native Proxy annotations when the selected exchange is already in history.
- Keep existing labels when applying a preview. Report conflicting labels and failed writes, and allow retries without duplicating successful writes.
- Prevent failed or ambiguous logins from starting a tracked session. Respect cookie expiration and response timing when carrying labels across requests.

## 1.0.1

- Illustrate how a selected value leads to exact matches and comparable values in captured traffic.
- Cancel active archive transfers and project settings work when the extension unloads.
- Include background search, archive, and project settings failures in the Burp extension error log.

## 1.0.0

First public release of HTTP Traffic Workbench for Burp Suite 2025.5 and later.

- Search requests and responses across Proxy history, project data, captured tool traffic, and imported archives.
- Follow identifiers across JSON, XML, HTML, forms, headers, cookies, and other message formats.
- Trace session cookies and preview user labels before applying them to Proxy history.
- Try the extension offline with the included synthetic traffic archive.

Install `http-traffic-workbench.jar` as a Java extension from **Extensions → Installed → Add**. See the [user guide](docs/user-guide.md) for installation and usage.
