# Offline walkthrough

The [demo archive](demo-traffic.tsv) contains seven fictional HTTP exchanges for `app.example.test`. Use **Import archive** in a blank Burp project. The examples run against the imported messages without sending HTTP requests.

## Follow a value across different field names

1. Open **Search all traffic**. Under **Sources**, enable **Extension archive** and **Repeater**.
2. Set **Mode** to **Auto**, leave **Depth** at **1**, and search for `demo-user-42`.
3. In **Direct matches**, compare the form field `username` on `/login` with `userId` in the login response. The response is JSON even though it is labeled `text/html`. The same value appears in an HTML input on `/account`, in JSON embedded on that page, and in XML and JavaScript responses.
4. Switch to **Related fields**. On `/activity`, `accountRef` holds `demo-user-84`, a different identifier with the same prefix and numeric width. You can also find `targetField=accountRef`, where an observed field name is stored as a literal value. These related rows score below direct matches.

Try **Field name** mode with `viewState` to find the HTML output control on `/account`. To try the search with message context, open a Burp message editor, select the name or value of a field, and right-click **HTTP Traffic Workbench · Search traffic for selection**.

## Trace a cookie

Open **Trace a cookie**, enter the cookie name `sid` and value `demo-session-a`, and run an exact trace. The trace finds the login response that sets the cookie, requests that send it, and the `/refresh` exchange that sets a replacement. Search again for `demo-session-b` to find the later activity and logout. Result rows display the cookie value as `Hidden`. The original message preview still shows the raw HTTP exchange.

## Label a user in Proxy history

The imported archive demonstrates search and exact cookie tracing. To try user labeling and replacement tracking, use a comparable login already in **Proxy → HTTP history**.

1. Right-click the login exchange and choose **HTTP Traffic Workbench · Use selected exchange as login**.
2. Choose **Response** as the user identifier source and `userId` as the field. Choose **Request** instead if the identifier comes from the submitted form.
3. Select the session cookie `sid` and set the optional end path to `/logout`.
4. Select **Preview** to review the proposed user notes. Use **Apply notes** to write them or **Save rule to project** to reuse the rule.

[Full user guide](../docs/user-guide.md)
