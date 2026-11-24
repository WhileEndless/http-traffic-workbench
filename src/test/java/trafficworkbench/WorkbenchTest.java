package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

final class WorkbenchTest {
    private static final String HOST = "app.example.test";
    private static final String USER = "user-7428";
    private static final String LOGIN = "/login";
    private static final String COOKIE = "sid";
    private static final long TIME = 1_760_000_000_000L;

    @BeforeEach
    void installFactory() {
        ObjectFactoryLocator.FACTORY = mock(MontoyaObjectFactory.class, (method, args) -> switch (method) {
            case "byteArray" -> bytes((byte[]) args[0]);
            case "httpRequestResponse" -> exchange((HttpRequest) args[0], (HttpResponse) args[1]);
            case "httpService" -> service((String) args[0], (int) args[1], (boolean) args[2]);
            case "httpRequest" -> requestFrom((HttpService) args[0], (ByteArray) args[1]);
            case "httpResponse" -> responseFrom((ByteArray) args[0]);
            case "requestResult" -> mock(burp.api.montoya.http.handler.RequestToBeSentAction.class,
                    (name, arguments) -> name.equals("request") ? args[0] : args[1]);
            case "responseResult" -> mock(burp.api.montoya.http.handler.ResponseReceivedAction.class,
                    (name, arguments) -> name.equals("response") ? args[0] : args[1]);
            default -> null;
        });
    }

    @Test
    void parsesJsonXmlFormAndMultipart() {
        assertEquals(List.of("nested", "7"), values("{\"obj\":{\"userId\":[\"nested\",7,null]}}", null, "userId"));
        assertEquals(List.of("A&B"), values("<ns:data xmlns:ns='urn:app'><ns:userId>A&amp;B</ns:userId></ns:data>",
                "application/soap+xml", "userId"));
        assertEquals(List.of("ü & M"), values("userId=%C3%BC+%26+M", null, "userId"));
        assertEquals(List.of(USER), values("--x\r\nContent-Disposition: form-data; name=\"userId\"\r\n\r\n"
                + USER + "\r\n--x--\r\n", "multipart/form-data; boundary=\"x\"", "userId"));
        assertEquals(List.of(USER), values("dto=%7B%22userId%22%3A%22" + USER + "%22%7D",
                "application/x-www-form-urlencoded", "userId"));
    }

    @Test
    void htmlControlsAndStaticScriptsAreSearchable() {
        String html = """
                <!doctype html><html><body>
                <input name="inputId" value="alpha&amp;beta">
                <output name="resultId">done</output>
                <textarea name="memo">some text</textarea>
                <select name="choice"><option value="blue">Blue</option><option>Red</option></select>
                <div data-user-code="U77"></div>
                <script>const identity = {"userId": 'from-js'}; const query = `plain`;
                const computed = `hidden-${expression}`; /* const commentValue = 'ignored'; */</script>
                </body></html>
                """;
        assertEquals(List.of("alpha&beta"), values(html, "text/html", "inputId"));
        assertTrue(values(html, "text/html", "resultId").contains("done"));
        assertTrue(values(html, "text/html", "memo").contains("some text"));
        assertTrue(values(html, "text/html", "choice").containsAll(List.of("blue", "Red")));
        assertEquals(List.of("U77"), values(html, "text/html", "user-code"));
        assertEquals(List.of("from-js"), values(html, "text/html", "userId"));
        assertEquals(List.of("plain"), values(html, "text/html", "query"));
        assertTrue(values(html, "text/html", "computed").isEmpty());
        assertTrue(values(html, "text/html", "commentValue").isEmpty());
        assertEquals(List.of("js-inline"), values("window.userId = 'js-inline';", "text/javascript", "userId"));
    }

    @Test
    void recognizesStructuredBodiesWhenTheDeclaredTypeIsWrong() {
        String json = "\uFEFF  {\"payload\":[{\"employeeId\":\"demo-42\"}]}";
        for (String type : List.of("text/html", "text/plain", "application/javascript", "application/xml",
                "application/x-www-form-urlencoded")) {
            assertEquals(List.of("demo-42"), values(json, type, "employeeId"));
        }
        assertEquals(List.of("visible-42"), values("<div>State: {&quot;employeeId&quot;:&quot;visible-42&quot;}</div>",
                "application/json", "employeeId"));
    }

    @Test
    void extractsEmbeddedJsonAndStaticJavascriptFromTheSameHtmlPage() {
        String html = """
                <html><body>
                <script type="application/json">{"session":{"memberCodes":["json-1","json-2"]}}</script>
                <pre>State: {&quot;visibleId&quot;:&quot;visible-42&quot;}</pre>
                <div data-state='{&quot;attributeId&quot;:&quot;attr-42&quot;}'></div>
                <!-- cached {"commentId":"comment-42"} -->
                <script>
                  // {"ignoredId":"comment-only"}
                  window.state = {"profiles":[{"accountIds":["inline-1","inline-2"]}]};
                  const count = 72;
                  const decoded = JSON.parse('{"decodedId":"decoded-42"}');
                </script>
                </body></html>
                """;
        assertEquals(List.of("json-1", "json-2"), values(html, "text/html", "memberCodes"));
        assertEquals(List.of("visible-42"), values(html, "text/html", "visibleId"));
        assertEquals(List.of("attr-42"), values(html, "text/html", "attributeId"));
        assertEquals(List.of("comment-42"), values(html, "text/html", "commentId"));
        assertEquals(List.of("inline-1", "inline-2"), values(html, "text/html", "accountIds"));
        assertEquals(List.of("72"), values(html, "text/html", "count"));
        assertEquals(List.of("decoded-42"), values(html, "text/html", "decodedId"));
        assertTrue(values(html, "text/html", "ignoredId").isEmpty());
    }

    @Test
    void fieldSearchAndUserExtractionBothReadJsonFromHtmlAndMislabeledResponses() {
        var req = request("GET", "/data", "", null, Map.of(), HOST);
        var misleading = response("{\"employeeId\":\"direct-42\"}", "text/html", Map.of());
        var html = response("<html><script type='application/json'>{\"employeeId\":\"nested-42\"}</script></html>",
                "text/plain", Map.of());
        var records = List.of(CapturedEntry.of("", exchange(req, misleading)), CapturedEntry.of("", exchange(req, html)));
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.RESPONSE, false, false,
                sink(matches)).runKey(List.of("employeeId"));
        assertEquals(List.of("direct-42", "nested-42"), matches.stream().map(row -> row.value).toList());
        var selected = SessionSuggestions.read(exchange(req, html));
        assertEquals("nested-42", selected.value(CaptureProfile.Source.RESPONSE, "employeeId"));
    }

    @Test
    void xmlDisablesDtdAndHandlesInvalidBodies() {
        String data = "<!DOCTYPE data [<!ENTITY external SYSTEM \"file:///missing-secret\">]>"
                + "<data><userId>&external;</userId></data>";
        assertTrue(values(data, "application/xml", "userId").isEmpty());
        assertTrue(values("{\"userId\":\"truncated\"", "application/json", "userId").isEmpty());
    }

    @Test
    void handlesGzipAndHeaderCharset() throws Exception {
        byte[] content;
        try (var out = new ByteArrayOutputStream()) {
            try (var gzip = new GZIPOutputStream(out)) {
                gzip.write("userId=caf%E9".getBytes(StandardCharsets.ISO_8859_1));
            }
            content = out.toByteArray();
        }
        var response = response(content, "application/x-www-form-urlencoded; charset=ISO-8859-1",
                Map.of("Content-Encoding", "gzip"));
        assertEquals(Set.of("userId"), FieldExtractor.keysForValue(Util.text(response, null).fields(), "café"));
    }

    @Test
    void profileCopiesAndValidates(@TempDir Path directory) throws Exception {
        var profile = profile(CaptureProfile.Source.RESPONSE_FIRST, "userId");
        Path file = directory.resolve("project.properties");
        Persistence.exportProfile(file, profile);
        assertEquals(profile, Persistence.importProfile(file));
        Files.writeString(file, "version=99");
        assertThrows(java.io.IOException.class, () -> Persistence.importProfile(file));
        var labeler = new UserLabeler();
        var req = request("POST", LOGIN, "userId=req-777", "application/x-www-form-urlencoded", Map.of(COOKIE, "a"), HOST);
        var res = response("<root><userId>response-777</userId></root>", "application/xml", Map.of());
        assertEquals("response-777", labeler.label(profile.compile(), req, res, 4096));
        assertEquals("req-777", labeler.label(profile(CaptureProfile.Source.REQUEST_FIRST, "userId").compile(), req, res, 4096));
        assertEquals("req-777", labeler.label(profile.compile(), req, null, 4096));
        assertEquals("", profile.compile().identify(new Util.MessageText("userId=a&userId=b", null, null, StandardCharsets.UTF_8)));
        assertEquals("", profile.compile().identify(new Util.MessageText(
                "{\"userId\":\"a\",\"userId\":\"b\"}", null, null, StandardCharsets.UTF_8)));
        assertEquals("abc", TimedRegex.group(TimedRegex.compile("id=(\\w+)"), "id=abc"));
        assertFalse(TimedRegex.finds(TimedRegex.compile("(a+)+b$"), "a".repeat(20_000)));
    }

    @Test
    void searchesAcrossFormatsDirectionsAndHostsWithoutLabels() {
        var req = request("POST", "/a", "{\"jsonId\":\"" + USER + "\"}", "application/json", Map.of(), HOST);
        var res = response("<root><xmlId>" + USER + "</xmlId></root>", "application/xml", Map.of());
        var form = request("POST", "/b", "formId=" + USER, "application/x-www-form-urlencoded", Map.of(), HOST);
        var script = response("const htmlId = '" + USER + "';", "application/javascript", Map.of());
        var records = List.of(CapturedEntry.of("", exchange(req, res)),
                CapturedEntry.of("", exchange(form, script)),
                CapturedEntry.of("", exchange(request("POST", "/b", "formId=" + USER,
                        "application/x-www-form-urlencoded", Map.of(), "another.example.test"), null)));
        var results = new ArrayList<ResultRow>();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(results))
                .runValue(USER, Set.of());
        assertEquals(List.of("jsonId", "xmlId", "formId", "htmlId", "formId"), results.stream().map(row -> row.key).toList());
        assertTrue(results.stream().allMatch(row -> row.userCode.isEmpty()));
        results.clear();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.RESPONSE, false, false, sink(results))
                .runText(USER.toUpperCase(), false);
        assertEquals(2, results.size());
        assertTrue(results.stream().allMatch(row -> row.source.equals("Response")));
    }

    @Test
    void findsRelatedFieldsAcrossFormatsAndShortExactValues() {
        var one = CapturedEntry.of("", exchange(request("POST", "/a",
                "{\"inputId\":[\"" + USER + "\",\"user-9999\"],\"flag\": true}", "application/json", Map.of(), HOST), null));
        var two = CapturedEntry.of("", exchange(request("POST", "/b", "", null, Map.of(), HOST),
                response("<data><mapped>user-9999</mapped></data>", "application/xml", Map.of())));
        var results = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(one, two), "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(results))
                .runValue(USER, Set.of("inputId"));
        assertTrue(results.stream().anyMatch(row -> row.key.equals("mapped") && row.reason.contains("Related")));
        results.clear();
        new ExtractEngine(List.of(one), "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(results))
                .runValue("true", Set.of());
        assertEquals(1, results.size());
        assertEquals("flag", results.get(0).key);
    }

    @Test
    void historicalReplayKeepsNotesAndIsolatesCookiesAndHosts() {
        var before = history("GET", "/dashboard", "s1", null, "", TIME, HOST);
        var login = history("POST", LOGIN, "", USER, "manual note", TIME + 1, HOST);
        var unrelated = history("GET", "/dashboard", "s2", null, "", TIME + 2, HOST);
        var otherHost = history("GET", "/dashboard", "s1", null, "", TIME + 3, "another.example.test");
        var active = history("GET", "/dashboard", "s1", null, "existing text", TIME + 4, HOST);
        var logout = history("POST", "/logout", "s1", null, "", TIME + 5, HOST);
        var after = history("GET", "/dashboard", "s1", null, "", TIME + 6, HOST);
        var input = List.of(after, logout, active, login, before, otherHost, unrelated);
        var profile = profile(CaptureProfile.Source.RESPONSE, "userId").compile();
        var plan = HistoryLabeler.plan(input, profile, () -> false, ignored -> {});
        assertEquals(3, plan.changes().size());
        assertEquals(1, plan.distinctUsers());
        assertEquals("existing text", active.annotations().notes());
        assertEquals(3, HistoryLabeler.apply(plan, () -> false, ignored -> {}));
        assertEquals("existing text\nUser: " + USER, active.annotations().notes());
        assertEquals("manual note\nUser: " + USER, login.annotations().notes());
        assertEquals("", after.annotations().notes());
        assertEquals("", otherHost.annotations().notes());
        assertEquals(0, HistoryLabeler.apply(plan, () -> false, ignored -> {}));
        assertEquals(0, HistoryLabeler.plan(input, profile, () -> true, ignored -> {}).scanned());
    }

    @Test
    void logoutRequiresConfiguredEvidenceAndEndsOnlyTheMatchingSession() {
        var logout = new LogoutRule("^/action$", "POST", "2xx, 302", "operation=logout", "\"loggedOut\":true");
        var settings = profile(CaptureProfile.Source.RESPONSE, "userId", Set.of(), logout);
        var login = history("POST", LOGIN, "", USER, "", TIME, HOST);
        var otherLogin = history("POST", LOGIN, "", "other-user", "", TIME + 1, HOST, "sid=s2; Path=/");
        var wrongMethod = logoutExchange("GET", "operation=logout", 200, true, TIME + 2);
        var otherAction = logoutExchange("POST", "operation=refresh", 200, true, TIME + 3);
        var rejected = logoutExchange("POST", "operation=logout", 403, true, TIME + 4);
        var notConfirmed = logoutExchange("POST", "operation=logout", 200, false, TIME + 5);
        var incomplete = logoutExchange("POST", "operation=logout", 0, false, TIME + 6);
        var stillActive = history("GET", "/account", "s1", null, "", TIME + 7, HOST);
        var confirmed = logoutExchange("POST", "operation=logout", 302, true, TIME + 8);
        var after = history("GET", "/account", "s1", null, "", TIME + 9, HOST);
        var other = history("GET", "/account", "s2", null, "", TIME + 10, HOST);
        var loginAgain = history("POST", LOGIN, "s1", "next-user", "", TIME + 11, HOST);
        var afterLogin = history("GET", "/account", "s1", null, "", TIME + 12, HOST);
        var sample = List.of(login, otherLogin, wrongMethod, otherAction, rejected, notConfirmed, incomplete,
                stillActive, confirmed, after, other, loginAgain, afterLogin);
        var plan = HistoryLabeler.plan(sample, settings.compile(), () -> false, ignored -> {});
        assertEquals(sample.size() - 1, HistoryLabeler.apply(plan, () -> false, ignored -> {}));
        assertEquals("User: " + USER, stillActive.annotations().notes());
        assertEquals("User: " + USER, confirmed.annotations().notes());
        assertEquals("", after.annotations().notes());
        assertEquals("User: other-user", other.annotations().notes());
        assertEquals("User: next-user", afterLogin.annotations().notes());
    }

    @Test
    void distinguishesLoginLogoutAndOtherOperationsOnTheSameRoute() {
        var logout = new LogoutRule("^/rpc$", "POST", "", "\"operation\":\"logout\"", "");
        var settings = new CaptureProfile(false, false, false, HOST, "", true, CaptureProfile.Source.RESPONSE,
                CaptureProfile.Locator.FIELD, "userId", "User", COOKIE, logout, "^/rpc$", "POST",
                "\"operation\":\"login\"", false, 30, Set.of()).compile();
        var labeler = new UserLabeler();
        var identity = response("{\"userId\":\"demo-user\"}", "application/json", Map.of());
        var ok = response("{}", "application/json", Map.of());
        var cookie = Map.of(COOKIE, "same");
        var login = request("POST", "/rpc", "{\"operation\":\"login\"}", "application/json", cookie, HOST);
        var query = request("POST", "/rpc", "{\"operation\":\"details\"}", "application/json", cookie, HOST);
        var quit = request("POST", "/rpc", "{\"operation\":\"logout\"}", "application/json", cookie, HOST);
        assertEquals("demo-user", labeler.label(settings, login, identity, Util.MAX_BODY_BYTES, TIME));
        assertEquals("demo-user", labeler.label(settings, query, ok, Util.MAX_BODY_BYTES, TIME + 1));
        assertEquals("demo-user", labeler.label(settings, quit, ok, Util.MAX_BODY_BYTES, TIME + 2));
        assertEquals("", labeler.label(settings, query, identity, Util.MAX_BODY_BYTES, TIME + 3));
    }

    @Test
    void logoutProfileRoundTripsAndKeepsLegacyPathOnlyBehavior() throws Exception {
        var simple = new LogoutRule("^/logout$", "POST", "", "", "");
        var current = profile(CaptureProfile.Source.RESPONSE, "userId", Set.of(), simple);
        assertEquals(current, CaptureProfile.decode(current.encode()));
        assertFalse(current.compile().logout().confirms(null, Util.MAX_BODY_BYTES));
        assertFalse(current.compile().logout().confirms(response(new byte[0], null, Map.of(), 500), Util.MAX_BODY_BYTES));
        assertTrue(current.compile().logout().confirms(response(new byte[0], null, Map.of(), 204), Util.MAX_BODY_BYTES));
        String oldFormat = current.encode().replace("version=2", "version=1")
                .replaceAll("(?m)^(?:end(?:Method|Statuses|RequestBody|ResponseBody)|identityRequestBody)=.*\\R", "");
        var legacy = CaptureProfile.decode(oldFormat);
        assertEquals(new LogoutRule("^/logout$", "", "any", "", ""), legacy.logout());
        assertTrue(legacy.compile().logout().confirms(null, Util.MAX_BODY_BYTES));
    }

    @Test
    void historicalReplayHonorsExpiryAndTransfersRotatedCookie() {
        var login = history("POST", LOGIN, "", USER, "", TIME, HOST);
        var rotate = history("GET", "/rotate", "s1", null, "", TIME + 1, HOST, "sid=s2; Path=/");
        var old = history("GET", "/old", "s1", null, "", TIME + 2, HOST);
        var next = history("GET", "/active", "s2", null, "", TIME + 4, HOST);
        var expires = history("GET", "/last", "s2", null, "", TIME + 5, HOST, "sid=; Max-Age=0");
        var expired = history("GET", "/expired", "s2", null, "", TIME + 6, HOST);
        var plan = HistoryLabeler.plan(List.of(login, rotate, old, next, expires, expired),
                profile(CaptureProfile.Source.RESPONSE, "userId").compile(), () -> false, ignore -> {});
        assertEquals(4, plan.changes().size());
        HistoryLabeler.apply(plan, () -> false, ignore -> {});
        assertEquals("", old.annotations().notes());
        assertEquals("", expired.annotations().notes());
        assertEquals("User: " + USER, next.annotations().notes());
    }

    @Test
    void loginWithoutIdentityDoesNotInheritOldUserAndTimeoutClosesSession() {
        var first = history("POST", LOGIN, "", USER, "", TIME, HOST);
        var missing = history("POST", LOGIN, "s1", null, "", TIME + 1, HOST);
        var old = history("GET", "/old", "s1", null, "", TIME + 2, HOST);
        var second = history("POST", LOGIN, "", USER, "", TIME + 3, HOST);
        var timedOut = history("GET", "/expired", "s1", null, "", TIME + 31 * 60_000, HOST);
        var profile = profile(CaptureProfile.Source.RESPONSE, "userId").compile();
        var plan = HistoryLabeler.plan(List.of(first, missing, old, second, timedOut), profile, () -> false, ignore -> {});
        assertEquals(2, plan.changes().size());
        HistoryLabeler.apply(plan, () -> false, ignore -> {});
        assertTrue(missing.annotations().notes().isEmpty());
        assertTrue(old.annotations().notes().isEmpty());
        assertTrue(timedOut.annotations().notes().isEmpty());
    }

    @Test
    void savesPerProjectAndTransfersLegacyArchive(@TempDir Path directory) throws Exception {
        var first = persistence();
        var second = persistence();
        var profile = profile(CaptureProfile.Source.RESPONSE, "userId");
        first.saveProfile(profile);
        assertEquals(profile, first.loadProfile());
        assertEquals(CaptureProfile.defaults(), second.loadProfile());
        var req = request("GET", "/archive", "", null, Map.of(), HOST);
        var record = CapturedEntry.of("", exchange(req, null), TIME);
        first.saveArchive(List.of(record));
        assertEquals("", first.loadArchive().get(0).userCode());
        assertEquals(0, second.loadArchive().size());
        var file = directory.resolve("archive.tsv");
        Persistence.exportArchive(file, List.of(record));
        assertEquals("/archive", Persistence.importArchive(file).get(0).path());
        String exported = Files.readString(file);
        assertTrue(exported.startsWith("# HTTP Traffic Workbench archive v2\n"));
        Files.writeString(file, exported.replace("# HTTP Traffic Workbench archive v2", "# Burp Advanced Search archive v2"));
        assertEquals("/archive", Persistence.importArchive(file).get(0).path());
        String raw = java.util.Base64.getEncoder().encodeToString(req.toByteArray().getBytes());
        Files.writeString(file, "legacy-user\t" + HOST + "\t443\ttrue\tGET\t/archive\t0\t" + TIME + "\t" + raw + "\t\n");
        assertEquals("legacy-user", Persistence.importArchive(file).get(0).userCode());
        first.saveProfile(CaptureProfile.defaults());
        assertTrue(first.loadArchive().isEmpty());
    }

    @Test
    void archiveDeduplicatesByHostAndKeepsLatestTenVariants() {
        var store = new CollectorStore(persistence());
        try {
            for (int i = 0; i < 20; i++) {
                var req = request("GET", "/same", "variant=" + i, null, Map.of(), HOST);
                store.add(CapturedEntry.of("", exchange(req, null), TIME + i));
            }
            var duplicate = request("GET", "/same", "variant=19", null, Map.of(), HOST);
            store.add(CapturedEntry.of("", exchange(duplicate, null), TIME + 30));
            var other = request("GET", "/same", "variant=19", null, Map.of(), "another.example.test");
            store.add(CapturedEntry.of("", exchange(other, null), TIME + 31));
            assertEquals(11, store.all().size());
            assertTrue(store.all().stream().anyMatch(entry -> entry.time() == TIME + 30));
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void scansTenThousandRecordsAndStopsCooperatively() {
        var timeline = new ArrayList<ProxyHttpRequestResponse>();
        timeline.add(history("POST", LOGIN, "", USER, "", TIME, HOST));
        for (int i = 1; i < 10_000; i++) {
            timeline.add(history("GET", "/dashboard", "s1", null, "", TIME + i, HOST));
        }
        var profile = profile(CaptureProfile.Source.RESPONSE, "userId").compile();
        var checks = new AtomicInteger();
        assertTrue(HistoryLabeler.plan(timeline, profile, () -> checks.incrementAndGet() > 10_400, ignored -> {}).scanned() < 10_000);
        var clock = java.lang.management.ManagementFactory.getThreadMXBean();
        long wallStart = System.nanoTime();
        long cpuStart = clock.getCurrentThreadCpuTime();
        assertEquals(10_000, HistoryLabeler.plan(timeline, profile, () -> false, ignored -> {}).changes().size());
        System.out.printf("Synthetic project replay, 10,000 records: %.0f ms elapsed, %.0f ms thread CPU%n",
                (System.nanoTime() - wallStart) / 1_000_000.0, (clock.getCurrentThreadCpuTime() - cpuStart) / 1_000_000.0);
    }

    @Test
    void discoversValuesFromLooseJsonAndKeepsDirectAndRelatedMatchesSeparate() {
        var first = CapturedEntry.of("", exchange(request("POST", "/sample", "{userId: 'demo-7428',}",
                "application/json", Map.of(), HOST), null));
        var second = CapturedEntry.of("", exchange(request("POST", "/sample", "userId=demo-9988",
                "application/x-www-form-urlencoded", Map.of(), HOST), response("<root><ref>demo-9988</ref></root>",
                "application/xml", Map.of())));
        var third = CapturedEntry.of("", exchange(request("GET", "/description", "", null, Map.of(), HOST),
                response("The identifier is DEMO-7428.", "text/plain", Map.of())));
        var results = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(first, first, second, third), "", 1, false, ExtractEngine.Direction.BOTH,
                true, true, sink(results)).runAuto("demo-7428", Set.of(), false);

        assertEquals(1, results.stream().filter(row -> row.key.equals("userId") && !row.related).count());
        assertTrue(results.stream().anyMatch(row -> row.key.equals("ref") && row.related));
        assertTrue(results.stream().anyMatch(row -> row.key.isEmpty() && row.value.contains("DEMO-7428")));
        assertTrue(Util.requestText(first.requestResponse()).fields().isEmpty());

        var pages = new ResultPages();
        pages.add(results);
        assertEquals(2, pages.size(ResultPages.Filter.DIRECT));
        assertTrue(pages.page(ResultPages.Filter.RELATED, 0).stream().allMatch(row -> row.related));
        assertFalse(pages.page(ResultPages.Filter.ALL, 0).get(0).related);
    }

    @Test
    void learnsNumericAliasesWithoutDumpingLoggingFieldsOrUnrelatedValues() {
        // Consecutive synthetic IDs preserve the numeric width across all message formats.
        String searched = "10000001";
        var submitted = request("POST", "/accounts", "accountId=" + searched,
                "application/x-www-form-urlencoded", Map.of(), HOST);
        var aliases = response("{\"AccountRef\":[" + searched + ",10000002,7,\"\",\"1/1\"],"
                        + "\"demo_event_extra_param_2\":[" + searched + ",10000003,10000004,\"\",\"1/1\"]}",
                "application/json", Map.of("X-Account-Id", searched, "Set-Cookie", "demo_sid=" + searched + "; Path=/"));
        var headerVariant = response("", "text/plain", Map.of("x-account-id", "10000005",
                "Set-Cookie", "demo_sid=10000006; Path=/"));
        var associated = response("<account><ref>10000002</ref><ref>10000007</ref><owner>10000004</owner>"
                        + "<selectedField>demo_event_extra_param_2</selectedField></account>",
                "application/xml", Map.of());
        var records = List.of(CapturedEntry.of("", exchange(submitted, aliases)),
                CapturedEntry.of("", exchange(request("GET", "/headers", "", null, Map.of("demo_sid", searched), HOST),
                        headerVariant)),
                CapturedEntry.of("", exchange(request("GET", "/linked", "", null, Map.of(), HOST), associated)));
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(records, CapturedEntry.endpoint(submitted), 1, false, ExtractEngine.Direction.BOTH,
                true, true, sink(matches)).runAuto(searched, Set.of("accountId"), false);

        assertTrue(matches.stream().anyMatch(row -> row.key.equals("demo_event_extra_param_2")
                && row.value.equals(searched) && !row.related));
        assertEquals(List.of("10000004"), matches.stream().filter(row -> row.related && row.key.equals("demo_event_extra_param_2"))
                .map(row -> row.value).toList());
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("selectedField")
                && row.reason.contains("Field name used as value")));
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("AccountRef")
                && row.value.equals("10000002")));
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("x-account-id")
                && row.value.equals("10000005") && row.reason.contains("Header")));
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("ref") && row.value.equals("10000002")));
        assertFalse(matches.stream().anyMatch(row -> row.value.isBlank()
                || Set.of("1/1", "10000007", "10000006", "10000003", "7").contains(row.value)));
        var cookies = matches.stream().filter(row -> row.key.equals("demo_sid")).toList();
        assertEquals(2, cookies.size());
        assertTrue(cookies.stream().allMatch(row -> row.value.equals("Hidden") && !row.related));
        assertTrue(cookies.stream().anyMatch(row -> row.reason.contains(" · Set-Cookie") && row.source.equals("Response")));
        assertTrue(cookies.stream().anyMatch(row -> row.reason.contains(" · Cookie") && row.source.equals("Request")));
        assertTrue(matches.stream().filter(row -> row.related).mapToInt(row -> row.relevance).max().orElseThrow()
                < matches.stream().filter(row -> !row.related).mapToInt(row -> row.relevance).min().orElseThrow());
    }

    @Test
    void autoUsesSelectedJsonOrFormKeysAndTheirValuesAcrossSources() {
        var form = request("POST", "/selected", "customerRef=demo-7428", "application/x-www-form-urlencoded", Map.of(), HOST);
        var json = response("{\"customerRef\":\"demo-7428\"}", "application/json", Map.of());
        var selected = exchange(form, json);
        var other = request("POST", "/lookup", "targetField=customerRef&reference=demo-7428&customerRef=",
                "application/x-www-form-urlencoded", Map.of(), HOST);
        var blank = request("POST", "/blank", "customerRef=", "application/x-www-form-urlencoded", Map.of(), HOST);
        var records = List.of(CapturedEntry.of("", exchange(other, null)), CapturedEntry.of("", exchange(blank, null)));
        for (boolean fromRequest : List.of(true, false)) {
            var context = HttpSearchFields.collect(selected, fromRequest);
            var matches = new ArrayList<ResultRow>();
            new ExtractEngine(records, "", 1, false, ExtractEngine.Direction.BOTH, true, true, sink(matches))
                    .runAutoFromContext("customerRef", context, false);
            assertTrue(matches.stream().anyMatch(row -> !row.related && row.key.equals("targetField")
                    && row.value.equals("customerRef")));
            assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("reference")
                    && row.value.equals("demo-7428")));
            assertEquals(4, matches.size());
            assertEquals(2, matches.stream().filter(row -> row.key.equals("customerRef") && row.value.isEmpty()).count());

            matches.clear();
            new ExtractEngine(records, "", 1, false, ExtractEngine.Direction.BOTH, true, true, sink(matches))
                    .runAutoFromContext("demo-7428", context, false);
            assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("targetField")));
            assertTrue(matches.stream().anyMatch(row -> !row.related && row.key.equals("reference")));
            assertEquals(2, matches.size());
        }
    }

    @Test
    void responseControlNamesAndExplicitIdsFollowEncodedValuesAcrossFormatsAndDepth() {
        var control = response("""
                <html><body>
                  <input name="cartItem" id="cart-entry-shell" value="sku%2f42">
                  <input name="otherItem" value="unrelated-77">
                </body></html>
                """, "text/html", Map.of());
        var page = exchange(request("GET", "/cart", "", null, Map.of(), HOST), control);
        var fields = HttpSearchFields.collect(page, false);
        var traffic = List.of(
                CapturedEntry.of("", exchange(request("POST", "/lookup", "{\"lookup\":\"sku/42\"}",
                        "application/json", Map.of(), HOST), response("<e><relay>sku%2F42</relay></e>", "application/xml", Map.of()))),
                CapturedEntry.of("", exchange(request("POST", "/edit", "{\"lookup\":\"sku/43\"}",
                        "application/json", Map.of(), HOST), null)),
                CapturedEntry.of("", exchange(request("POST", "/stock", "stock=sku%2f43&extra=unrelated-77",
                        "application/x-www-form-urlencoded", Map.of(), HOST), null)),
                CapturedEntry.of("", exchange(request("POST", "/script", "{\"scriptReference\":\"cart-entry-shell\"}",
                        "application/json", Map.of(), HOST), null)));
        for (String name : List.of("cartItem", "cart-entry-shell")) {
            var rows = new ArrayList<ResultRow>();
            new ExtractEngine(traffic, "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                    .runKeyFromContext(List.of(name), fields);
            assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("lookup") && row.value.equals("sku/42")));
            assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("relay")
                    && row.source.equals("Response") && row.value.equals("sku%2F42")));
            assertFalse(rows.stream().anyMatch(row -> row.key.equals("stock") || row.key.equals("extra")));

            rows.clear();
            new ExtractEngine(traffic, "", 2, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                    .runAutoFromContext(name, fields, false);
            assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("stock")
                    && row.value.equals("sku%2f43")));
        }

        var rows = new ArrayList<ResultRow>();
        var withPage = new ArrayList<>(traffic);
        withPage.add(CapturedEntry.of("", page));
        new ExtractEngine(withPage, "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAuto("cart-entry-shell", Set.of(), false);
        assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("lookup")));
        rows.clear();
        new ExtractEngine(withPage, "", 2, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAutoFromContext("sku/42", fields, false);
        assertFalse(rows.stream().anyMatch(row -> row.related && row.key.equals("scriptReference")));
    }

    @Test
    void responseValueCanCorroborateTheSameKeyFromAnIdOnlyControl() {
        var page = exchange(request("GET", "/preview", "", null, Map.of(), HOST),
                response("<input id=\"recordField\" value=\"item-42\">", "text/html", Map.of()));
        var other = exchange(request("POST", "/edit", "{\"recordField\":\"item-43\"}",
                "application/json", Map.of(), HOST), null);
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(CapturedEntry.of("", page), CapturedEntry.of("", other)), "", 1, false,
                ExtractEngine.Direction.BOTH, false, false, sink(matches)).runAuto("item-42", Set.of(), false);
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("recordField")
                && row.value.equals("item-43")));
    }

    @Test
    void sameMatchRetainsBothMessageSidesAndEachSideUsesItsOwnSpelling() throws Exception {
        var request = request("POST", "/submit", "item=part%2f42", "application/x-www-form-urlencoded", Map.of(), HOST);
        var response = response("{\"item\":\"part/42\"}", "application/json", Map.of());
        var exchange = exchange(request, response);
        for (var direction : ExtractEngine.Direction.values()) {
            var rows = new ArrayList<ResultRow>();
            new ExtractEngine(List.of(CapturedEntry.of("", exchange)), "", 0, false, direction,
                    false, true, sink(rows)).runValue("part/42", Set.of());
            assertEquals(direction == ExtractEngine.Direction.BOTH ? 2 : 1, rows.size());
            assertEquals(rows.size(), rows.stream().map(row -> row.id).distinct().count());
            for (var row : rows) {
                String spelling = row.source.equals("Request") ? "part%2f42" : "part/42";
                assertEquals(spelling, row.value);
                assertEquals(spelling, row.editorSearch);
                if (direction == ExtractEngine.Direction.REQUEST) assertEquals("Request", row.source);
                if (direction == ExtractEngine.Direction.RESPONSE) assertEquals("Response", row.source);
            }
        }

        javax.swing.SwingUtilities.invokeAndWait(() -> {
            var requestTerm = new AtomicReference<>("");
            var responseTerm = new AtomicReference<>("");
            var requestEditor = mock(burp.api.montoya.ui.editor.HttpRequestEditor.class, (name, args) -> {
                if (name.equals("setSearchExpression")) requestTerm.set((String) args[0]);
                return name.equals("uiComponent") ? new javax.swing.JPanel() : null;
            });
            var responseEditor = mock(burp.api.montoya.ui.editor.HttpResponseEditor.class, (name, args) -> {
                if (name.equals("setSearchExpression")) responseTerm.set((String) args[0]);
                return name.equals("uiComponent") ? new javax.swing.JPanel() : null;
            });
            var ui = mock(burp.api.montoya.ui.UserInterface.class, (name, args) ->
                    name.equals("createHttpRequestEditor") ? requestEditor : responseEditor);
            var view = new ExchangeView(mock(MontoyaApi.class, (name, args) -> ui));
            view.show(exchange, "part%2f42", "");
            assertEquals("part%2f42", requestTerm.get());
            assertEquals("", responseTerm.get());
            view.show(exchange, "", "part/42");
            assertEquals("", requestTerm.get());
            assertEquals("part/42", responseTerm.get());
        });
    }

    @Test
    void completedExchangeUpdatesTheDisplayedFormSpellingOfACollapsedMatch() {
        var incomplete = CapturedEntry.of("", exchange(request("POST", "/submit", "item=part%2f42",
                "application/x-www-form-urlencoded", Map.of(), HOST), null));
        var complete = CapturedEntry.of("", exchange(request("POST", "/submit", "item=part%2F42",
                "application/x-www-form-urlencoded", Map.of(), HOST), response("done", "text/plain", Map.of())));
        var results = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(incomplete, complete), "", 0, false, ExtractEngine.Direction.REQUEST,
                false, true, sink(results)).runValue("part/42", Set.of());
        assertEquals(2, results.size());
        assertEquals(results.get(0).id, results.get(1).id);
        var pages = new ResultPages();
        pages.add(results);
        var row = pages.page(ResultPages.Filter.ALL, 0).get(0);
        assertEquals("part%2F42", row.value);
        assertEquals("part%2F42", row.editorSearch);
        assertSame(complete, row.entry);
    }

    @Test
    void followsExplicitTextValuesWithoutADateOrIdentifierShape() {
        var origin = response("<input name=\"entryLabel\" value=\"Caf%C3%A9%20du%20matin\">",
                "text/html", Map.of());
        var selected = exchange(request("GET", "/item", "", null, Map.of(), HOST), origin);
        var another = CapturedEntry.of("", exchange(request("POST", "/search", "lookup=Caf%C3%A9+du+matin",
                "application/x-www-form-urlencoded", Map.of(), HOST),
                response("<item><caption>Café du matin</caption><other>Café du soir</other></item>",
                        "application/xml", Map.of())));
        var rows = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(another), "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAutoFromContext("entryLabel", HttpSearchFields.collect(selected, false), false);
        assertEquals(Set.of("lookup", "caption"), rows.stream().map(row -> row.key)
                .collect(java.util.stream.Collectors.toSet()));
        assertTrue(rows.stream().allMatch(row -> row.related));
    }

    @Test
    void knownFieldVariantsAppearBeforeTheNextEntryIsRead() {
        var early = CapturedEntry.of("", exchange(request("POST", "/first", "entry=item-83",
                "application/x-www-form-urlencoded", Map.of(), HOST), null));
        var late = CapturedEntry.of("", exchange(request("POST", "/second", "{\"entry\":\"item-84\"}",
                "application/json", Map.of(), HOST), null));
        var rows = new ArrayList<ResultRow>();
        var entries = new java.util.AbstractList<CapturedEntry>() {
            @Override public int size() { return 2; }
            @Override public CapturedEntry get(int index) {
                if (index == 0) return early;
                assertEquals(List.of("item-83"), rows.stream().filter(row -> row.related).map(row -> row.value).toList());
                return late;
            }
        };
        var selected = FieldExtractor.searchPairs("entry=item-82", "application/x-www-form-urlencoded", null,
                StandardCharsets.UTF_8);
        new ExtractEngine(entries, "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAutoFromContext("item-82", selected, false);
        assertEquals(List.of("item-83", "item-84"), rows.stream().map(row -> row.value).toList());
    }

    @Test
    void followsFormFieldsEmbeddedInJsonAndXmlAndDecodesEntityValues() {
        var first = CapturedEntry.of("", exchange(request("POST", "/submit", "order%24ref=item%26%2347%3B83&view=public",
                "application/x-www-form-urlencoded", Map.of(), HOST),
                response("{\"payload\":\"tracking=item%2F83&view=public\",\"order%24ref\":\"item/83\"}",
                        "application/json", Map.of())));
        var next = CapturedEntry.of("", exchange(request("GET", "/later", "", null, Map.of(), HOST),
                response("<data><payload><![CDATA[confirmation=item%2f83&view=public]]></payload>"
                        + "<reference>order%24ref</reference></data>", "application/xml", Map.of())));
        var rows = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(first, next), "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAuto("order%24ref", Set.of(), false);
        assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("tracking") && row.value.equals("item%2F83")));
        assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("confirmation") && row.value.equals("item%2f83")));
        rows.clear();
        new ExtractEngine(List.of(first, next), "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAuto("item/83", Set.of(), false);
        assertTrue(rows.stream().anyMatch(row -> row.related && row.key.equals("reference")));
    }

    @Test
    void selectedProxyExchangeReplacesOneNativeCopyButKeepsOtherHistoryRows() {
        var exchange = exchange(request("POST", "/item", "entry=sample", "application/x-www-form-urlencoded",
                Map.of(), HOST), null);
        var selected = CapturedEntry.of("", exchange, 0, TrafficSource.PROXY, 0, false);
        var first = CapturedEntry.of("", exchange, TIME, TrafficSource.PROXY, 8090, false);
        var second = CapturedEntry.of("", exchange, TIME + 1, TrafficSource.PROXY, 8090, false);
        assertEquals(List.of(selected, second), TrafficCatalog.includeSelected(java.util.stream.Stream.of(first, second),
                selected).toList());
    }

    @Test
    void archiveShortcutAppearsForToolTrafficAndLoggerButNotProxyHistory() {
        var store = new CollectorStore(persistence());
        var api = mock(MontoyaApi.class, (name, args) -> null);
        try {
            var menu = new SearchContextMenu(api, store, CaptureProfile::defaults, config -> {});
            try {
                var exchange = exchange(request("GET", "/item", "", null, Map.of(), HOST), null);
                for (var tool : List.of(burp.api.montoya.core.ToolType.PROXY, burp.api.montoya.core.ToolType.TARGET,
                        burp.api.montoya.core.ToolType.REPEATER, burp.api.montoya.core.ToolType.LOGGER)) {
                    var event = mock(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (name, args) -> switch (name) {
                        case "toolType" -> tool;
                        case "selectedRequestResponses" -> List.of(exchange);
                        case "messageEditorRequestResponse" -> java.util.Optional.empty();
                        default -> null;
                    });
                    var labels = menu.provideMenuItems(event).stream().map(javax.swing.JMenuItem.class::cast)
                            .map(javax.swing.JMenuItem::getText).toList();
                    assertEquals(tool == burp.api.montoya.core.ToolType.REPEATER || tool == burp.api.montoya.core.ToolType.LOGGER,
                            labels.stream().anyMatch(label -> label.endsWith("Archive this exchange")));
                    assertTrue(labels.stream().anyMatch(label -> label.contains("Search traffic")));
                }
            } finally {
                menu.close();
            }
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void searchesEncodedFormDatesAndFieldNamesAcrossBodyFormats() {
        String encodedKey = "demo01%24WorkspaceContent%24InventoryFilter2%24FromDateControl%24DateInput";
        String key = encodedKey.replace("%24", "$");
        String date = "17/08/2018";
        String formType = "application/x-www-form-urlencoded";
        var submitted = request("POST", "/filter", encodedKey + "=17%2F08%2F2018", formType, Map.of(), HOST);
        var selected = exchange(submitted, null);
        var records = List.of(
                CapturedEntry.of("", selected),
                CapturedEntry.of("", exchange(request("POST", "/json", "{\"startDate\":\"" + date + "\"}",
                        "application/json", Map.of(), HOST), response("<dates><from>18/08/2018</from>"
                        + "<unrelated>19/08/2018</unrelated><field>" + key + "</field></dates>", "application/xml", Map.of()))),
                CapturedEntry.of("", exchange(request("POST", "/next", encodedKey + "=18%2F08%2F2018", formType,
                        Map.of(), HOST), response("<input name=\"fromDate\" value=\"" + date + "\">", "text/html", Map.of()))),
                CapturedEntry.of("", exchange(request("POST", "/multipart", "--b\r\nContent-Disposition: form-data; "
                        + "name=\"multipartDate\"\r\n\r\n" + date + "\r\n--b--\r\n",
                        "multipart/form-data; boundary=b", Map.of(), HOST),
                        response("const scriptDate = '" + date + "';", "application/javascript", Map.of()))),
                CapturedEntry.of("", exchange(request("POST", "/invalid", encodedKey + "=31%2F02%2F2018", formType,
                        Map.of(), HOST), null)));
        for (String query : List.of("17%2F08%2F2018", "17%2f08%2f2018", date)) {
            var matches = new ArrayList<ResultRow>();
            new ExtractEngine(records, "", 1, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                    .runAuto(query, Set.of(), false);
            assertEquals(Set.of(key, "startDate", "fromDate", "multipartDate", "scriptDate"),
                    matches.stream().filter(row -> !row.related && SearchEncoding.url(row.value).equals(date))
                            .map(row -> row.key).collect(java.util.stream.Collectors.toSet()));
            assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals(key)
                    && row.value.equals("18%2F08%2F2018")));
            assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("from")
                    && row.value.equals("18/08/2018")));
            assertFalse(matches.stream().anyMatch(row -> row.key.equals("unrelated")
                    || SearchEncoding.url(row.value).equals("31/02/2018")));
        }

        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(records.subList(1, records.size()), "", 1, false, ExtractEngine.Direction.BOTH,
                false, true, sink(matches)).runAutoFromContext("17%2F08%2F2018", HttpSearchFields.collect(selected, true), false);
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals(key) && row.value.equals("18%2F08%2F2018")));
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("field") && row.value.equals(key)));

        matches.clear();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                .runKey(List.of(encodedKey));
        assertEquals(3, matches.size());
        assertTrue(matches.stream().allMatch(row -> row.key.equals(key)));

        matches.clear();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                .runValueFromContext("17%2F08%2F2018", List.of());
        assertEquals(5, matches.size());
        assertTrue(matches.stream().allMatch(row -> !row.related && SearchEncoding.url(row.value).equals(date)));
    }

    @Test
    void findsKnownDateFieldsAcrossUrlsAndFormatsWhenTheDiscoveryIndexIsFull() {
        String field = "windowStart";
        String submitted = "16%2F09%2F2017";
        String formType = "application/x-www-form-urlencoded";
        var original = exchange(request("POST", "/submit", field + "=" + submitted, formType, Map.of(), HOST), null);
        var beforeLimit = CapturedEntry.of("", exchange(request("POST", "/search",
                "{\"windowStart\":\"2021-09-16\"}", "application/json", Map.of(), HOST), null));
        var laterForm = CapturedEntry.of("", exchange(request("POST", "/submit", field + "=16%2F09%2F2022",
                formType, Map.of(), HOST), null));
        var laterXml = CapturedEntry.of("", exchange(request("GET", "/results", "", null, Map.of(), HOST),
                response("<range><windowStart>16.9.2023</windowStart><unrelated>16.9.2024</unrelated></range>",
                        "application/xml", Map.of())));
        var exactAlias = CapturedEntry.of("", exchange(request("POST", "/report",
                "{\"openingDate\":\"16/09/2017\"}", "application/json", Map.of(), HOST), null));
        String padding = "x".repeat(1_950);
        String noisyBody = "{\"padding\":[" + String.join(",", java.util.Collections.nCopies(850, '"' + padding + '"')) + "]}";
        var noisy = CapturedEntry.of("", exchange(request("POST", "/background", noisyBody,
                "application/json", Map.of(), HOST), null));
        var entries = new ArrayList<CapturedEntry>();
        entries.add(beforeLimit);
        entries.addAll(java.util.Collections.nCopies(8, noisy));
        entries.addAll(List.of(CapturedEntry.of("", original), laterForm, laterXml, exactAlias));

        var matches = new ArrayList<ResultRow>();
        var passes = new AtomicInteger();
        Iterable<CapturedEntry> traffic = () -> {
            passes.incrementAndGet();
            return entries.iterator();
        };
        var engine = new ExtractEngine(traffic, entries.size(), "", 1, false, ExtractEngine.Direction.BOTH,
                false, false, sink(matches));
        engine.runAuto(submitted, Set.of(), false);
        assertTrue(engine.discoveryLimited());
        assertEquals(1, passes.get());
        assertEquals(Set.of("2021-09-16", "16%2F09%2F2022", "16.9.2023"),
                matches.stream().filter(row -> row.related && row.key.equals(field)).map(row -> row.value)
                        .collect(java.util.stream.Collectors.toSet()));
        assertEquals(3, matches.stream().filter(row -> row.related && row.key.equals(field)).count());
        assertTrue(matches.stream().anyMatch(row -> !row.related && row.key.equals("openingDate")));
        assertFalse(matches.stream().anyMatch(row -> row.key.equals("unrelated")));

        matches.clear();
        new ExtractEngine(entries, "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(matches))
                .runAutoFromContext(field, HttpSearchFields.collect(original, true), false);
        assertTrue(matches.stream().anyMatch(row -> row.related && row.key.equals("openingDate")));

        matches.clear();
        new ExtractEngine(List.of(beforeLimit, laterForm, laterXml), "", 1, false,
                ExtractEngine.Direction.BOTH, false, false, sink(matches))
                .runAutoFromContext(submitted, HttpSearchFields.collect(original, true), false);
        assertEquals(Set.of("/search", "/submit", "/results"), matches.stream().filter(row -> row.related)
                .map(row -> row.entry.path()).collect(java.util.stream.Collectors.toSet()));
    }

    @Test
    void recoversKnownFieldsIfComparableValuesExceedTheirOwnBudget() {
        String body = "{\"unrelated\":[" + String.join(",", java.util.Collections.nCopies(16_000, "\"2031-08-16\"")) + "]}";
        var unrelated = CapturedEntry.of("", exchange(request("POST", "/background", body, "application/json",
                Map.of(), HOST), null));
        var known = CapturedEntry.of("", exchange(request("POST", "/known", "when=16%2F08%2F2020",
                "application/x-www-form-urlencoded", Map.of(), HOST), null));
        var variant = CapturedEntry.of("", exchange(request("POST", "/variant", "{\"when\":\"2023-08-16\"}",
                "application/json", Map.of(), HOST), null));
        var passes = new AtomicInteger();
        Iterable<CapturedEntry> traffic = () -> {
            passes.incrementAndGet();
            return List.of(unrelated, unrelated, known, variant).iterator();
        };
        var rows = new ArrayList<ResultRow>();
        new ExtractEngine(traffic, 4, "", 1, false, ExtractEngine.Direction.BOTH, false, false, sink(rows))
                .runAuto("16%2F08%2F2020", Set.of(), false);
        assertEquals(2, passes.get());
        assertEquals(List.of("16%2F08%2F2020", "2023-08-16"), rows.stream().map(row -> row.value).toList());
        assertTrue(rows.get(1).related);
    }

    @Test
    void encodedFormNamesAreFoundEvenWhenEmptyAndPreviewUsesOriginalSpelling() {
        String wireKey = "demo01%24WorkspaceContent%24InventoryFilter2%24FromDateControl%24DateInput";
        String decodedKey = wireKey.replace("%24", "$");
        String formType = "application/x-www-form-urlencoded";
        var request = request("POST", "/filter", "page=2&\r\n" + wireKey + "=17%2f08%2F2018&submit=yes",
                formType, Map.of(), HOST);
        var response = response(wireKey + "=&page=2", "application/javascript", Map.of());
        var bareName = request("GET", "/filter?" + wireKey, "", null, Map.of(), HOST);
        var html = response("<input name=\"" + wireKey + "\" value=\"\">", "text/html", Map.of());
        var entries = List.of(CapturedEntry.of("", exchange(request, response)),
                CapturedEntry.of("", exchange(bareName, html)));
        for (String query : List.of(wireKey, decodedKey)) {
            var matches = new ArrayList<ResultRow>();
            new ExtractEngine(entries, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(matches))
                    .runAuto(query, Set.of(), false);
            assertEquals(List.of("Request", "Response", "Request", "Response"), matches.stream().map(row -> row.source).toList());
            assertTrue(matches.stream().allMatch(row -> row.editorSearch.equals(wireKey)));
            assertEquals(List.of("17%2f08%2F2018", "", "", ""), matches.stream().map(row -> row.value).toList());

            matches.clear();
            new ExtractEngine(entries, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(matches))
                    .runKey(List.of(query));
            assertEquals(4, matches.size());
        }

        var values = new ArrayList<ResultRow>();
        new ExtractEngine(entries, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(values))
                .runAuto("17%2F08%2F2018", Set.of(), false);
        assertEquals(1, values.size());
        assertEquals("17%2f08%2F2018", values.get(0).editorSearch);

        var echoed = CapturedEntry.of("", exchange(bareName,
                response("The submitted field was " + wireKey + ".", "text/plain", Map.of())));
        var textMatches = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(echoed), "", 0, false, ExtractEngine.Direction.RESPONSE, false, false, sink(textMatches))
                .runAuto(decodedKey, Set.of(), false);
        assertEquals(1, textMatches.size());
        assertEquals(wireKey, textMatches.get(0).editorSearch);
    }

    @Test
    void encodedSearchKeepsLiteralValuesAndDecodesTheQueryOnlyOnce() {
        var json = response("""
                {"literal":"a%252Fb", "decodedOnce":"a%2Fb", "decodedTwice":"a/b",
                "malformed":"100%xx", "mixed":"%xx/"}
                """, "application/json", Map.of());
        var records = List.of(CapturedEntry.of("", exchange(request("GET", "/values", "", null, Map.of(), HOST), json)));
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                .runAuto("a%252Fb", Set.of(), false);
        assertEquals(List.of("literal", "decodedOnce"), matches.stream().map(row -> row.key).toList());

        matches.clear();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                .runAuto("100%xx", Set.of(), false);
        assertEquals(List.of("malformed"), matches.stream().map(row -> row.key).toList());

        matches.clear();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                .runAuto("%xx%2F", Set.of(), false);
        assertEquals(List.of("mixed"), matches.stream().map(row -> row.key).toList());
    }

    @Test
    void searchesEmbeddedFormsMultipartAndTextFieldsWithNonAsciiValues() {
        String value = "café + tea";
        String encoded = "caf%C3%A9+%2B+tea";
        var form = request("POST", "/form", "formLabel=" + encoded + "&doc=%7B%22embeddedLabel%22%3A%22"
                + encoded + "%22%7D", "application/x-www-form-urlencoded", Map.of(), HOST);
        var text = response("first=other\nproperty=" + encoded + "\ntextLabel: " + value, "text/plain", Map.of());
        var multipart = "MIME preamble\r\n--outer\r\nContent-Disposition: form-data; name=\"package\"\r\n"
                + "Content-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\n"
                + "Content-Type: application/json\r\n\r\n{\"nestedLabel\":\"" + value + "\"}\r\n"
                + "--inner--\r\n--outer--\r\n";
        var records = List.of(CapturedEntry.of("", exchange(form, text)),
                CapturedEntry.of("", exchange(request("POST", "/multipart", multipart, "multipart/form-data; boundary=outer",
                        Map.of(), HOST), null)));
        for (String query : List.of(encoded, value)) {
            var matches = new ArrayList<ResultRow>();
            new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                    .runAuto(query, Set.of(), false);
            assertEquals(Set.of("formLabel", "embeddedLabel", "property", "textLabel", "nestedLabel"),
                    matches.stream().map(row -> row.key).collect(java.util.stream.Collectors.toSet()));
            assertEquals(Map.of("formLabel", encoded, "property", encoded, "embeddedLabel", value,
                    "textLabel", value, "nestedLabel", value),
                    matches.stream().collect(java.util.stream.Collectors.toMap(row -> row.key, row -> row.value)));
        }
    }

    @Test
    void autoFindsEquivalentUrlAndHtmlSpellingsInFieldsAndText() {
        String raw = "17/08/2018";
        String url = "17%2F08%2F2018";
        String html = "17&#47;08&#x2f;2018";
        var json = response("""
                {"startDate":"17/08/2018", "urlDate":"17%2f08%2f2018",
                 "htmlDate":"17&#47;08&#x2f;2018", "namedDate":"17&sol;08&sol;2018",
                 "nestedEncoding":"17%252F08%252F2018", "start%24field":"selected"}
                """, "application/json", Map.of());
        var text = response("Selected date was " + html + ".", "text/plain", Map.of());
        var records = List.of(CapturedEntry.of("", exchange(request("GET", "/json", "", null, Map.of(), HOST), json)),
                CapturedEntry.of("", exchange(request("GET", "/text", "", null, Map.of(), HOST), text)));
        for (String query : List.of(raw, url, html)) {
            var results = new ArrayList<ResultRow>();
            new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(results))
                    .runAuto(query, Set.of(), false);
            var keys = results.stream().map(row -> row.key).filter(key -> !key.isEmpty())
                    .collect(java.util.stream.Collectors.toSet());
            assertTrue(keys.containsAll(Set.of("startDate", "urlDate", "htmlDate", "namedDate")));
            assertEquals(query.equals(url), keys.contains("nestedEncoding"));
            assertTrue(results.stream().anyMatch(row -> row.key.isEmpty() && row.value.contains("Selected date")
                    && row.editorSearch.equals(html)));
        }

        var results = new ArrayList<ResultRow>();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(results))
                .runKey(List.of("start&#36;field"));
        assertEquals(List.of("start%24field"), results.stream().map(row -> row.key).toList());
        assertEquals("café+tea", SearchEncoding.html("caf&eacute;&plus;tea"));
        assertEquals("café+tea", SearchEncoding.url("caf%C3%A9+tea"));
    }

    @Test
    void searchPanelFindsTheSelectedRepeaterRequestWithoutCapturedTraffic() throws Exception {
        String encoded = "17%2F08%2F2018";
        String key = "demo01$WorkspaceContent$InventoryFilter2$FromDateControl$DateInput";
        var request = request("POST", "/filter", key.replace("$", "%24") + "=" + encoded,
                "application/x-www-form-urlencoded", Map.of(), HOST);
        var selected = exchange(request, null);
        var store = new CollectorStore(persistence());
        var scans = new ScanQueue();
        var panel = new AtomicReference<SearchPanel>();
        var visible = new java.util.concurrent.CountDownLatch(1);
        var rawSearch = new java.util.concurrent.CountDownLatch(1);
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var ui = offscreenUi(term -> {
                    if (encoded.equals(term)) rawSearch.countDown();
                });
                var api = mock(MontoyaApi.class, (name, args) -> ui);
                var context = new ExtractDialog.Context("", CapturedEntry.endpoint(request),
                        () -> HttpSearchFields.collect(selected, true), null,
                        new ExtractDialog.SelectedExchange(selected, TrafficSource.REPEATER));
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults,
                        ExtractDialog.Dataset.ALL, context, () -> {});
                panel.set(search);
                find(search, SourcePicker.class).select(Set.of(TrafficSource.REPEATER));
                find(search, javax.swing.JTextField.class).setText(encoded);
                var table = find(search, javax.swing.JTable.class);
                table.getModel().addTableModelListener(event -> {
                    if (table.getRowCount() > 0) visible.countDown();
                });
                button(search, "Search").doClick();
            });
            assertTrue(visible.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var table = find(panel.get(), javax.swing.JTable.class);
                assertEquals("Repeater", table.getModel().getValueAt(0, 3));
                assertEquals("Request", table.getModel().getValueAt(0, 4));
                assertEquals(key, table.getModel().getValueAt(0, 5));
                assertEquals(encoded, table.getModel().getValueAt(0, 6));
                table.setRowSelectionInterval(0, 0);
            });
            assertTrue(rawSearch.await(3, java.util.concurrent.TimeUnit.SECONDS));
            assertTrue(store.all().isEmpty());
        } finally {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                if (panel.get() != null) panel.get().close();
            });
            scans.close();
            store.flushAndShutdown();
        }
    }

    @Test
    void selectedFormCharsetProvidesAnExactMatchAcrossTrafficSources() {
        var form = exchange(request("POST", "/source", "caf%E9Label=caf%E9",
                "application/x-www-form-urlencoded; charset=ISO-8859-1", Map.of(), HOST), null);
        var json = response("{\"caféLabel\":\"café\"}", "application/json", Map.of());
        var records = List.of(CapturedEntry.of("", exchange(request("GET", "/json", "", null, Map.of(), HOST), json)));
        var fields = HttpSearchFields.collect(form, true);
        for (String query : List.of("caf%E9", "caf%E9Label")) {
            var matches = new ArrayList<ResultRow>();
            new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, true, sink(matches))
                    .runAutoFromContext(query, fields, false);
            assertEquals(1, matches.size());
            assertEquals("caféLabel", matches.get(0).key);
            assertEquals("café", matches.get(0).value);
        }
    }

    @Test
    void headerNameMatchingIsCaseInsensitiveAndProtectedHeaderResultsAreMasked() {
        var request = request("GET", "/headers", "", null, Map.of(), HOST);
        var response = response("", "text/plain", Map.of("X-Account-Id", "demo-9071",
                "Authorization", "Bearer demo-9071-private"));
        var entries = List.of(CapturedEntry.of("", exchange(request, response)));
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(entries, "", 0, false, ExtractEngine.Direction.BOTH, true, true, sink(matches))
                .runKey(List.of("x-account-id"));
        assertEquals(1, matches.size());
        assertEquals("X-Account-Id", matches.get(0).key);
        assertEquals("demo-9071", matches.get(0).value);
        matches.clear();
        new ExtractEngine(entries, "", 0, false, ExtractEngine.Direction.BOTH, true, true, sink(matches))
                .runAuto("demo-9071", Set.of(), false);
        var authorization = matches.stream().filter(row -> row.key.equals("Authorization")).findFirst().orElseThrow();
        assertEquals("Hidden", authorization.value);
        assertEquals("Authorization", authorization.editorSearch);
    }

    @Test
    void searchPanelShowsFirstResultWhileTheSecondHistoryRecordIsStillLoading() throws Exception {
        var persistence = persistence();
        var store = new CollectorStore(persistence);
        var scans = new ScanQueue();
        var firstVisible = new java.util.concurrent.CountDownLatch(1);
        var releaseSecond = new java.util.concurrent.CountDownLatch(1);
        var secondVisible = new java.util.concurrent.CountDownLatch(1);
        var searchFilled = new java.util.concurrent.CountDownLatch(1);
        var first = history("POST", "/search-one", "", USER, "", TIME, HOST);
        var second = history("POST", "/search-two", "", USER, "", TIME + 1, HOST);
        var records = new java.util.AbstractList<ProxyHttpRequestResponse>() {
            @Override public int size() { return 2; }

            @Override public ProxyHttpRequestResponse get(int index) {
                if (index == 0) return first;
                try {
                    if (!releaseSecond.await(5, java.util.concurrent.TimeUnit.SECONDS)) {
                        throw new AssertionError("The second record was not released.");
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    return first;
                }
                return second;
            }
        };
        var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> records);
        var ui = offscreenUi(value -> {
            if (USER.equals(value)) searchFilled.countDown();
        });
        var api = mock(MontoyaApi.class, (name, args) -> name.equals("proxy") ? proxy : ui);
        var panel = new AtomicReference<SearchPanel>();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults,
                        ExtractDialog.Dataset.HISTORY, new ExtractDialog.Context(USER, "", List::of), () -> {});
                panel.set(search);
                var table = find(search, javax.swing.JTable.class);
                assertNotNull(table);
                table.getModel().addTableModelListener(event -> {
                    if (table.getRowCount() == 1) firstVisible.countDown();
                    if (table.getRowCount() == 2) secondVisible.countDown();
                });
                render(search, 780, 600, "search-start");
                search.searchSelection();
            });
            assertTrue(firstVisible.await(3, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(1, secondVisible.getCount());
            javax.swing.SwingUtilities.invokeAndWait(() ->
                    find(panel.get(), javax.swing.JTable.class).setRowSelectionInterval(0, 0));
            assertTrue(searchFilled.await(3, java.util.concurrent.TimeUnit.SECONDS));
            releaseSecond.countDown();
            assertTrue(secondVisible.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> render(panel.get(), 1050, 710, "search-results"));
        } finally {
            releaseSecond.countDown();
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                if (panel.get() != null) panel.get().close();
            });
            scans.close();
            store.flushAndShutdown();
        }
    }

    @Test
    void fieldMatchUpgradesToACompleteExchangeWithoutAddingADuplicate() {
        var first = request("POST", "/inspect?trace=first", "userId=demo-7", "application/x-www-form-urlencoded",
                Map.of(), HOST);
        var second = request("POST", "/inspect?trace=completed", "userId=demo-7",
                "application/x-www-form-urlencoded", Map.of(), HOST);
        var answer = response("paired reply", "text/plain", Map.of());
        var incomplete = CapturedEntry.of("", exchange(first, null), TIME);
        var completed = CapturedEntry.of("", exchange(second, answer), TIME + 1);
        var results = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(incomplete, completed), "", 1, false, ExtractEngine.Direction.BOTH, false, true,
                sink(results)).runKey(List.of("userId"));

        assertEquals(2, results.size());
        assertEquals(results.get(0).id, results.get(1).id);
        assertEquals("Field match", results.get(1).reason);
        var pages = new ResultPages();
        pages.add(results);
        assertEquals(1, pages.size(ResultPages.Filter.ALL));
        var row = pages.page(ResultPages.Filter.ALL, 0).get(0);
        assertSame(answer, row.entry.requestResponse().response());
        assertSame(second, row.entry.requestResponse().request());
        assertTrue(row.endpoint.endsWith("trace=completed"));
    }

    @Test
    void emptySearchDoesNotReadTrafficUntilBrowseIsChosen() throws Exception {
        var calls = new AtomicInteger();
        var finished = new java.util.concurrent.CountDownLatch(1);
        var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> {
            calls.incrementAndGet();
            return List.of(history("GET", "/sample", "", null, "", TIME, HOST));
        });
        var ui = offscreenUi();
        var api = mock(MontoyaApi.class, (name, args) -> name.equals("proxy") ? proxy : ui);
        var scans = new ScanQueue();
        var store = new CollectorStore(persistence());
        var panel = new AtomicReference<SearchPanel>();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults,
                        ExtractDialog.Dataset.HISTORY, ExtractDialog.Context.empty(), () -> {});
                panel.set(search);
                search.searchSelection();
                assertTrue(button(search, "Browse traffic").isVisible());
                assertFalse(button(search, "Search").isVisible());
                assertFalse(button(search, "Stop").isVisible());
                assertEquals(0, calls.get());
                button(search, "Stop").addPropertyChangeListener("enabled", event -> {
                    if (Boolean.FALSE.equals(event.getNewValue())) finished.countDown();
                });
                button(search, "Browse traffic").doClick();
            });
            assertTrue(finished.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var search = panel.get();
                assertEquals(1, calls.get());
                assertEquals(1, find(search, javax.swing.JTable.class).getRowCount());
                var query = find(search, javax.swing.JTextField.class);
                query.setText("pending");
                assertTrue(button(search, "Search").isVisible());
                query.setText("");
                assertEquals(0, find(search, javax.swing.JTable.class).getRowCount());
                assertEquals(1, calls.get());
            });
        } finally {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                if (panel.get() != null) panel.get().close();
            });
            scans.close();
            store.flushAndShutdown();
        }
    }

    @Test
    void sameHostFiltersProxyHistoryAndSearchControlsHideAfterCompletion() throws Exception {
        var selectedRequest = request("GET", "/origin", "", null, Map.of(), HOST.toUpperCase(java.util.Locale.ROOT));
        var same = history("GET", "/match?q=needle", "", null, "", TIME, HOST);
        var other = history("GET", "/another?q=needle", "", null, "", TIME + 1, "other.example.test");
        var records = List.of(same, other);
        var entered = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var firstFinished = new java.util.concurrent.CountDownLatch(1);
        var secondFinished = new java.util.concurrent.CountDownLatch(2);
        var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> {
            if (args == null || args.length == 0) return records;
            entered.countDown();
            try {
                if (!release.await(3, java.util.concurrent.TimeUnit.SECONDS)) throw new AssertionError("Search was not released");
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return List.of();
            }
            var filter = (burp.api.montoya.proxy.ProxyHistoryFilter) args[0];
            return records.stream().filter(filter::matches).toList();
        });
        var ui = offscreenUi();
        var api = mock(MontoyaApi.class, (name, args) -> name.equals("proxy") ? proxy : ui);
        var store = new CollectorStore(persistence());
        var scans = new ScanQueue();
        var panel = new AtomicReference<SearchPanel>();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var context = new ExtractDialog.Context("needle", CapturedEntry.endpoint(selectedRequest), List::of, null,
                        new ExtractDialog.SelectedExchange(exchange(selectedRequest, null), TrafficSource.REPEATER));
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults,
                        ExtractDialog.Dataset.HISTORY, context, () -> {});
                panel.set(search);
                var host = find(search, javax.swing.JCheckBox.class, box -> box.getText().equals("Same host"));
                assertTrue(host.isSelected());
                assertTrue(host.isEnabled());
                var stop = button(search, "Stop");
                var progress = find(search, javax.swing.JProgressBar.class);
                assertFalse(stop.isVisible());
                assertFalse(progress.isVisible());
                stop.addPropertyChangeListener("enabled", event -> {
                    if (Boolean.FALSE.equals(event.getNewValue())) {
                        firstFinished.countDown();
                        secondFinished.countDown();
                    }
                });
                search.searchSelection();
                assertTrue(stop.isVisible());
                assertTrue(progress.isVisible());
            });
            assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS));
            release.countDown();
            assertTrue(firstFinished.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var search = panel.get();
                assertFalse(button(search, "Stop").isVisible());
                assertFalse(find(search, javax.swing.JProgressBar.class).isVisible());
                var table = find(search, javax.swing.JTable.class);
                assertEquals(1, table.getRowCount());
                assertTrue(table.getValueAt(0, 2).toString().contains(HOST));
                find(search, javax.swing.JCheckBox.class, box -> box.getText().equals("Same host")).doClick();
            });
            assertTrue(secondFinished.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var search = panel.get();
                assertEquals(2, find(search, javax.swing.JTable.class).getRowCount());
                assertFalse(button(search, "Stop").isVisible());
                assertFalse(find(search, javax.swing.JProgressBar.class).isVisible());
            });
        } finally {
            release.countDown();
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                if (panel.get() != null) panel.get().close();
            });
            scans.close();
            store.flushAndShutdown();
        }
    }

    @Test
    void selectedFieldMatchLoadsTheResponseWhenItsDuplicateIsUpgraded() throws Exception {
        var store = new CollectorStore(persistence());
        var scans = new ScanQueue();
        var firstVisible = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var responseLoaded = new java.util.concurrent.CountDownLatch(1);
        var query = "POST /inspect";
        var first = request("POST", "/inspect?state=pending", "userId=demo", "application/x-www-form-urlencoded",
                Map.of(), HOST);
        var second = request("POST", "/inspect?state=complete", "userId=demo", "application/x-www-form-urlencoded",
                Map.of(), HOST);
        var answer = response("paired reply", "text/plain", Map.of());
        java.util.function.BiFunction<HttpRequest, HttpResponse, ProxyHttpRequestResponse> nativeRow = (req, res) ->
                mock(ProxyHttpRequestResponse.class, (name, args) -> switch (name) {
                    case "request", "finalRequest" -> req;
                    case "response" -> res;
                    case "listenerPort" -> 8080;
                    default -> null;
                });
        var records = new java.util.AbstractList<ProxyHttpRequestResponse>() {
            @Override public int size() { return 2; }
            @Override public ProxyHttpRequestResponse get(int index) {
                if (index == 0) return nativeRow.apply(first, null);
                try {
                    if (!release.await(5, java.util.concurrent.TimeUnit.SECONDS)) {
                        throw new AssertionError(query + " response was not released.");
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
                return nativeRow.apply(second, answer);
            }
        };
        var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> records);
        var baseUi = offscreenUi();
        var editor = mock(burp.api.montoya.ui.editor.HttpResponseEditor.class, (name, args) -> {
            if (name.equals("setResponse") && args[0] == answer) responseLoaded.countDown();
            return name.equals("uiComponent") ? new javax.swing.JPanel() : null;
        });
        var ui = mock(burp.api.montoya.ui.UserInterface.class, (name, args) ->
                name.equals("createHttpResponseEditor") ? editor : baseUi.createHttpRequestEditor());
        var api = mock(MontoyaApi.class, (name, args) -> name.equals("proxy") ? proxy : ui);
        var panel = new AtomicReference<SearchPanel>();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults, ExtractDialog.Dataset.HISTORY,
                        new ExtractDialog.Context("userId", "", () -> List.of(new FieldExtractor.Pair("userId", "demo", 0))),
                        () -> {});
                panel.set(search);
                find(search, javax.swing.JCheckBox.class, box -> box.getText().equals("Collapse repeated matches")).setSelected(true);
                var table = find(search, javax.swing.JTable.class);
                table.getModel().addTableModelListener(event -> {
                    if (table.getRowCount() == 1) firstVisible.countDown();
                });
                search.searchSelection();
            });
            assertTrue(firstVisible.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() ->
                    find(panel.get(), javax.swing.JTable.class).setRowSelectionInterval(0, 0));
            release.countDown();
            assertTrue(responseLoaded.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var table = find(panel.get(), javax.swing.JTable.class);
                assertEquals(1, table.getRowCount());
                assertEquals(0, table.getSelectedRow());
                assertTrue(table.getValueAt(0, 2).toString().endsWith("state=complete"));
            });
        } finally {
            release.countDown();
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                if (panel.get() != null) panel.get().close();
            });
            scans.close();
            store.flushAndShutdown();
        }
    }

    @Test
    void incompleteArchiveResultCanResolveItsOwnLaterResponse() {
        var store = new CollectorStore(persistence());
        try {
            var request = request("GET", "/in-flight", "", null, Map.of(), HOST);
            var response = response("late reply", "text/plain", Map.of());
            var pending = CapturedEntry.of("", exchange(request, null), TIME);
            pending.awaitCompletion();
            store.add(pending);
            var snapshot = store.all().get(0);
            assertTrue(snapshot.awaitingResponse());

            store.addCompleted(pending, CapturedEntry.of("", exchange(request, response), TIME + 1));
            assertFalse(snapshot.awaitingResponse());
            assertSame(response, snapshot.latest().requestResponse().response());
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void originalProxyResponseIsUsedWhenTheFinalResponseIsMissing() {
        var request = request("POST", LOGIN, "userId=original-user", "application/x-www-form-urlencoded", Map.of(), HOST);
        var answer = response("original", "text/plain", Map.of());
        var record = mock(ProxyHttpRequestResponse.class, (name, args) -> switch (name) {
            case "request", "finalRequest" -> request;
            case "originalResponse" -> answer;
            case "listenerPort" -> 8080;
            default -> null;
        });
        var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> List.of(record));
        var api = mock(MontoyaApi.class, (name, args) -> proxy);
        var store = new CollectorStore(persistence());
        try {
            var entry = new TrafficCatalog(api, store).stream(Set.of(TrafficSource.PROXY), "User").findFirst().orElseThrow();
            assertSame(answer, entry.requestResponse().response());
            var chosen = new SessionAnchor(exchange(request, null), CaptureProfile.Source.REQUEST, "original-user")
                    .resolve(List.of(record), () -> false);
            assertSame(record, chosen.item());
            assertSame(answer, chosen.exchange().response());
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void selectedLoginSeparatesRequestAndResponseFieldsAndCookieOrigins() {
        var request = request("POST", LOGIN + "?employeeId=request-user", "name=one",
                "application/x-www-form-urlencoded", Map.of("incoming", "first"), HOST);
        var answer = response("{\"userId\":\"response-user\"}", "application/json",
                Map.of("Set-Cookie", "sid=second; Path=/"));
        var suggestions = SessionSuggestions.read(exchange(request, answer));

        assertEquals("employeeId", suggestions.matchingField(CaptureProfile.Source.REQUEST, "request-user"));
        assertEquals("userId", suggestions.matchingField(CaptureProfile.Source.RESPONSE, "response-user"));
        assertFalse(suggestions.fields(CaptureProfile.Source.REQUEST).contains("userId"));
        assertEquals("response-user", suggestions.value(CaptureProfile.Source.RESPONSE, "userId"));
        assertEquals("request-user", suggestions.value(CaptureProfile.Source.REQUEST, "employeeId"));
        assertEquals("sid", suggestions.recommendCookie());
        assertEquals("Set by the response.", suggestions.cookieLocation("sid"));
        assertEquals("Sent in the request.", suggestions.cookieLocation("incoming"));
    }

    @Test
    void exactHistoryAnchorUsesTimingAndRejectsAmbiguousDuplicates() {
        var older = history("POST", LOGIN, "s1", USER, "", TIME, HOST);
        var newer = history("POST", LOGIN, "s1", USER, "", TIME + 60, HOST);
        var separateRequest = request("POST", LOGIN, "", null, Map.of("sid", "s1"), HOST);
        var anchor = new SessionAnchor(exchange(separateRequest, null), CaptureProfile.Source.REQUEST, "");
        assertTrue(anchor.resolve(List.of(older, newer), () -> false).ambiguous());

        var selected = mock(HttpRequestResponse.class, (name, args) -> switch (name) {
            case "request" -> separateRequest;
            case "timingData" -> java.util.Optional.of(newer.timingData());
            default -> null;
        });
        assertSame(newer, new SessionAnchor(selected, null, "").resolve(List.of(older, newer), () -> false).item());
    }

    @Test
    void selectedSessionStartsAtTheChosenLoginAndDoesNotStartOtherSessions() {
        var priorLogin = history("POST", LOGIN, "", "prior-user", "", TIME, HOST);
        var priorActivity = history("GET", "/account", "s1", null, "", TIME + 5, HOST);
        var selected = history("POST", LOGIN, "", USER, "", TIME + 10, HOST, "sid=s2; Path=/");
        var otherLogin = history("POST", LOGIN, "", "other-user", "", TIME + 11, HOST, "sid=s3; Path=/");
        var selectedActivity = history("GET", "/account", "s2", null, "", TIME + 12, HOST);
        var otherActivity = history("GET", "/account", "s3", null, "", TIME + 13, HOST);
        var laterLogin = history("POST", LOGIN, "s2", "next-user", "", TIME + 14, HOST, "sid=s2; Path=/");
        var laterActivity = history("GET", "/account", "s2", null, "", TIME + 15, HOST);

        var rule = profile(CaptureProfile.Source.RESPONSE, "userId").compile();
        var history = List.of(otherActivity, selected, priorLogin, selectedActivity, otherLogin, priorActivity,
                laterLogin, laterActivity);
        var plan = HistoryLabeler.plan(history, rule, selected, () -> false, ignored -> {});
        assertEquals(2, HistoryLabeler.apply(plan, () -> false, ignored -> {}));
        assertEquals("User: " + USER, selected.annotations().notes());
        assertEquals("User: " + USER, selectedActivity.annotations().notes());
        for (var untouched : List.of(priorLogin, priorActivity, otherLogin, otherActivity, laterLogin, laterActivity)) {
            assertTrue(untouched.annotations().notes().isEmpty());
        }
    }

    @Test
    void largeResponseCanBeLoadedFromThePreviewOnDemand() throws Exception {
        var loaded = new AtomicReference<HttpResponse>();
        var responseEditor = mock(burp.api.montoya.ui.editor.HttpResponseEditor.class, (name, args) -> {
            if (name.equals("setResponse")) loaded.set((HttpResponse) args[0]);
            return name.equals("uiComponent") ? new javax.swing.JPanel() : null;
        });
        var common = offscreenUi();
        var ui = mock(burp.api.montoya.ui.UserInterface.class, (name, args) -> switch (name) {
            case "createHttpRequestEditor" -> common.createHttpRequestEditor();
            case "createHttpResponseEditor" -> responseEditor;
            default -> null;
        });
        var api = mock(MontoyaApi.class, (name, args) -> ui);
        var request = request("GET", "/large", "", null, Map.of(), HOST);
        var response = response("x".repeat(2 * 1024 * 1024 + 1), "text/plain", Map.of());
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            var view = new ExchangeView(api);
            view.show(exchange(request, response), "x");
            assertNull(loaded.get());
            var button = button(view.component(), "Load full response");
            assertNotNull(button);
            assertTrue(button.isVisible());
            button.doClick();
            assertSame(response, loaded.get());
            view.show(exchange(request, null));
            assertFalse(button.isVisible());
        });
    }

    @Test
    void exactCookieTraceUsesOnlyMatchingHeadersAndKeepsTheValueOutOfResults() {
        var named = request("GET", "/target", "", null, Map.of("sid", "demo-cookie"), HOST);
        var response = response("", "text/plain", Map.of("Set-Cookie", "sid=demo-cookie; Path=/"));
        var textOnly = request("POST", "/body", "sid=demo-cookie", "application/x-www-form-urlencoded", Map.of(), HOST);
        var otherService = request("GET", "/other", "", null, Map.of("sid", "demo-cookie"), "other.example.test");
        var wrongCase = request("GET", "/case", "", null, Map.of("SID", "demo-cookie"), HOST);
        var prefixOnly = request("GET", "/prefix", "", null, Map.of("sid", "demo-cookie-extra"), HOST);
        var records = List.of(CapturedEntry.of("", exchange(named, response)),
                CapturedEntry.of("", exchange(textOnly, null)), CapturedEntry.of("", exchange(otherService, null)),
                CapturedEntry.of("", exchange(wrongCase, null)), CapturedEntry.of("", exchange(prefixOnly, null)));
        var matches = new ArrayList<ResultRow>();
        var trace = new CookieTrace("sid", "demo-cookie", named.httpService());
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, false,
                sink(matches)).runCookie(trace, ignored -> true);
        assertEquals(List.of("Request Cookie", "Response Set-Cookie"), matches.stream().map(row -> row.reason).toList());
        assertTrue(matches.stream().allMatch(row -> row.value.equals("Hidden") && row.editorSearch.equals("sid")));
        assertFalse(trace.toString().contains("demo-cookie"));
        assertFalse(Cookies.fields(named, false).get(0).toString().contains("demo-cookie"));
    }

    @Test
    void cookieTraceFollowsAnObservedReplacementEvenWhenItsRowIsFiltered() {
        var initial = request("POST", "/login", "", null, Map.of(), HOST);
        var old = request("POST", "/rotate", "", null, Map.of("sid", "token-a"), HOST);
        var active = request("GET", "/activity", "", null, Map.of("sid", "token-b"), HOST);
        var quit = request("POST", "/logout", "", null, Map.of("sid", "token-b"), HOST);
        var after = request("GET", "/after", "", null, Map.of("sid", "token-b"), HOST);
        var records = List.of(
                CapturedEntry.of("", exchange(initial, response("", null, Map.of("Set-Cookie", "sid=token-a"))), TIME),
                CapturedEntry.of("", exchange(old, response("", null, Map.of("Set-Cookie", "sid=token-b"))), TIME + 1),
                CapturedEntry.of("", exchange(active, null), TIME + 2),
                CapturedEntry.of("", exchange(quit, response("", null,
                        Map.of("Set-Cookie", "sid=expired; Expires=Thu, 01 Jan 1970 00:00:00 GMT"))), TIME + 3),
                CapturedEntry.of("", exchange(after, null), TIME + 4));
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(matches))
                .runCookie(new CookieTrace("sid", "token-a", initial.httpService(), true),
                        entry -> !entry.path().equals("/rotate"));
        assertEquals(List.of("/login", "/activity", "/logout", "/logout"),
                matches.stream().map(row -> row.entry.path()).toList());
        assertEquals("Response Set-Cookie · removed", matches.get(3).reason);
    }

    @Test
    void cookieRemovalUsesMaxAgeBeforeExpires() {
        var kept = response("", null, Map.of("Set-Cookie",
                "sid=value; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=120"));
        var removed = response("", null, Map.of("Set-Cookie",
                "sid=value; Expires=Wed, 01 Jan 2050 00:00:00 GMT; Max-Age=0"));
        assertFalse(Cookies.fields(kept, true).get(0).expiredAt(TIME));
        assertTrue(Cookies.fields(removed, true).get(0).expiredAt(TIME));
    }

    @Test
    void shippedAnonymousArchiveExercisesHtmlXmlAndJavaScriptSearch() throws Exception {
        var demo = Persistence.importArchive(Path.of("examples", "demo-traffic.tsv"));
        assertEquals(7, demo.size());
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(demo, "", 1, false, ExtractEngine.Direction.BOTH, true, true, sink(matches))
                .runAuto("demo-user-42", Set.of(), false);
        var paths = matches.stream().filter(row -> !row.related).map(row -> row.entry.path()).toList();
        assertTrue(paths.containsAll(List.of("/login", "/account", "/profile.xml", "/assets/account.js")));
        assertTrue(matches.stream().anyMatch(row -> row.entry.source() == TrafficSource.REPEATER
                && row.key.equals("accountRef")));
        assertTrue(matches.stream().anyMatch(row -> row.related && row.entry.path().equals("/activity")
                && row.key.equals("accountRef") && row.value.equals("demo-user-84")));
        assertTrue(matches.stream().anyMatch(row -> row.related && row.entry.path().equals("/activity")
                && row.key.equals("targetField") && row.reason.contains("Field name used as value")));
    }

    @Test
    void scoreColorsRemainDistinctOnLightAndDarkThemes() throws Exception {
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            var table = new javax.swing.JTable(4, 1);
            var renderer = new SearchResultRenderer(true);
            for (var background : List.of(java.awt.Color.WHITE, new java.awt.Color(0x23262B))) {
                table.setBackground(background);
                table.setForeground(background.equals(java.awt.Color.WHITE) ? java.awt.Color.BLACK : java.awt.Color.WHITE);
                var colors = new java.util.HashSet<java.awt.Color>();
                for (int score : new int[]{100, 85, 65, 40}) {
                    var component = renderer.getTableCellRendererComponent(table, score, false, false, 0, 0);
                    assertTrue(component.getFont().isBold());
                    colors.add(component.getForeground());
                }
                assertEquals(4, colors.size());
            }
            var selected = renderer.getTableCellRendererComponent(table, 100, true, false, 0, 0);
            assertEquals(table.getSelectionForeground(), selected.getForeground());
        });
    }

    @Test
    void defaultSearchShowsRepeatedAndRelatedProxyFormsWithoutInferringDomIdReferences() throws Exception {
        String formName = "demo01$WorkspaceContent$InventoryFilter2$FromDateControl$DateInput";
        String wireName = formName.replace("$", "%24");
        String domId = formName.replace('$', '_');
        String route = "/demo/records.aspx";
        var opener = request("GET", route + "?view=7", "", null, Map.of(), HOST);
        var rendered = response("""
                <html><body>
                <!-- ClientID: demo01_WorkspaceContent_InventoryFilter2_FromDateControl, Version: demo -->
                <input name="%s" type="text" value="17/08/2018" id="%s" onkeypress="dpKeyPress(this,event);" />
                <script>const inputID = '%s';</script>
                </body></html>
                """.formatted(formName, domId, domId), "text/html", Map.of());
        var selected = exchange(opener, rendered);
        var records = java.util.stream.IntStream.rangeClosed(1, 3).mapToObj(i -> {
            String date = i == 3 ? "18%2f08%2f2018" : "17%2f08%2f2018";
            var form = request("POST", route + "?view=" + i, "clientState=example&" + wireName + "=" + date,
                    "application/x-www-form-urlencoded; charset=UTF-8", Map.of(), HOST);
            return history(form, response("", "text/plain", Map.of()), "", TIME + i);
        }).toList();
        var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> records);
        var ui = offscreenUi();
        var api = mock(MontoyaApi.class, (name, args) -> name.equals("proxy") ? proxy : ui);
        var store = new CollectorStore(persistence());
        var scans = new ScanQueue();
        var panel = new AtomicReference<SearchPanel>();
        var completed = new java.util.concurrent.CountDownLatch(1);
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var context = new ExtractDialog.Context("17%2F08%2F2018", CapturedEntry.endpoint(opener),
                        () -> HttpSearchFields.collect(selected, false), null,
                        new ExtractDialog.SelectedExchange(selected, TrafficSource.REPEATER));
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults,
                        ExtractDialog.Dataset.ALL, context, () -> {});
                panel.set(search);
                find(search, SourcePicker.class).select(Set.of(TrafficSource.PROXY, TrafficSource.REPEATER));
                assertTrue(hasComboSelection(search, "All matches"));
                var stop = button(search, "Stop");
                stop.addPropertyChangeListener("enabled", event -> {
                    if (Boolean.FALSE.equals(event.getNewValue())) completed.countDown();
                });
                search.searchSelection();
            });
            assertTrue(completed.await(3, java.util.concurrent.TimeUnit.SECONDS));
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var table = find(panel.get(), javax.swing.JTable.class);
                var proxyUrls = new HashSet<String>();
                for (int i = 0; i < table.getRowCount(); i++) {
                    assertNotEquals("inputID", table.getValueAt(i, 5));
                    if (table.getValueAt(i, 3).equals("Proxy history")) {
                        assertEquals(formName, table.getValueAt(i, 5));
                        proxyUrls.add(table.getValueAt(i, 2).toString());
                        if (table.getValueAt(i, 2).toString().endsWith("view=3")) {
                            assertEquals("18%2f08%2f2018", table.getValueAt(i, 6));
                        }
                    }
                }
                assertEquals(3, proxyUrls.size());
            });
        } finally {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                if (panel.get() != null) panel.get().close();
            });
            scans.close();
            store.flushAndShutdown();
        }
    }

    @Test
    void editorSearchUsesTheMatchedTextAndFallsBackToTheFieldName() {
        var first = CapturedEntry.of("", exchange(request("GET", "/a", "", null, Map.of(), HOST),
                response("Text around MatchedWord goes here.", "text/plain", Map.of())));
        var second = CapturedEntry.of("", exchange(request("POST", "/b",
                "{\"description\":\"" + "large-".repeat(200) + "\"}", "application/json", Map.of(), HOST), null));
        var matches = new ArrayList<ResultRow>();
        new ExtractEngine(List.of(first, second), "", 0, false, ExtractEngine.Direction.BOTH, false, false,
                sink(matches)).runText("matchedword", false);
        assertEquals("MatchedWord", matches.get(0).editorSearch);
        matches.clear();
        new ExtractEngine(List.of(second), "", 0, false, ExtractEngine.Direction.BOTH, false, false,
                sink(matches)).runKey(List.of("description"));
        assertEquals("description", matches.get(0).editorSearch);
    }

    @Test
    void capturesOnlySelectedToolsAndCompletesRequestPairs() throws Exception {
        var store = new CollectorStore(persistence());
        try {
            var configured = profile(CaptureProfile.Source.RESPONSE, "userId", Set.of(TrafficSource.EXTENSIONS));
            assertEquals(configured, CaptureProfile.decode(configured.encode()));
            var compiled = configured.compile();
            var capture = new ToolTrafficCapture(() -> compiled, store, Runnable::run, ex -> fail(ex));
            var req = request("POST", "/tools", "userId=tool-value", "application/x-www-form-urlencoded", Map.of(), HOST);
            var resp = response("tool-response", "text/plain", Map.of());
            var notes = annotations("User: tool-value");
            for (var tool : List.of(burp.api.montoya.core.ToolType.PROXY, burp.api.montoya.core.ToolType.REPEATER,
                    burp.api.montoya.core.ToolType.EXTENSIONS)) {
                var source = mock(burp.api.montoya.core.ToolSource.class, (name, args) -> tool);
                var sent = mock(burp.api.montoya.http.handler.HttpRequestToBeSent.class, (name, args) -> switch (name) {
                    case "toolSource" -> source;
                    case "messageId" -> 7;
                    case "annotations" -> notes;
                    case "httpService" -> req.httpService();
                    case "url" -> req.url();
                    case "method" -> req.method();
                    case "pathWithoutQuery" -> req.pathWithoutQuery();
                    case "body" -> req.body();
                    case "toByteArray" -> req.toByteArray();
                    default -> null;
                });
                assertSame(sent, capture.handleHttpRequestToBeSent(sent).request());
                if (tool != burp.api.montoya.core.ToolType.EXTENSIONS) {
                    assertTrue(store.all().isEmpty());
                    continue;
                }
                assertEquals(1, store.all().size());
                assertNull(store.all().get(0).requestResponse().response());
                var received = mock(burp.api.montoya.http.handler.HttpResponseReceived.class, (name, args) -> switch (name) {
                    case "toolSource" -> source;
                    case "messageId" -> 7;
                    case "annotations" -> notes;
                    case "initiatingRequest" -> req;
                    case "statusCode" -> resp.statusCode();
                    case "body" -> resp.body();
                    case "toByteArray" -> resp.toByteArray();
                    default -> null;
                });
                assertSame(received, capture.handleHttpResponseReceived(received).response());
                assertEquals(1, store.all().size());
                var archived = store.all().get(0);
                assertEquals(TrafficSource.EXTENSIONS, archived.source());
                assertEquals("tool-value", archived.userCode());
                assertTrue(archived.annotated());
                assertNotNull(archived.requestResponse().response());
            }
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void searchesCombinedProjectSourcesAndFiltersByToolAndHttpMetadata() {
        var store = new CollectorStore(persistence());
        try {
            var nativeProxy = history("GET", "/proxy", "", USER, "note", TIME, HOST);
            var request = request("POST", "/asset.json", "posting=yes", null, Map.of(), HOST);
            var exchange = exchange(request, response("remote response " + USER, "application/json", Map.of()));
            var proxy = mock(burp.api.montoya.proxy.Proxy.class, (name, args) -> List.of(nativeProxy));
            var finding = mock(burp.api.montoya.scanner.audit.issues.AuditIssue.class, (name, args) -> List.of(exchange));
            var map = mock(burp.api.montoya.sitemap.SiteMap.class, (name, args) ->
                    name.equals("issues") ? List.of(finding) : List.of(exchange));
            var api = mock(MontoyaApi.class, (name, args) -> name.equals("proxy") ? proxy : map);
            store.add(CapturedEntry.of("", exchange, TIME, TrafficSource.SCANNER, 0, true));
            store.add(CapturedEntry.of("", exchange, TIME + 1, TrafficSource.EXTENSIONS, 0, false));
            var catalog = new TrafficCatalog(api, store);
            Set<TrafficSource> enabled = Set.of(TrafficSource.PROXY, TrafficSource.SITE_MAP, TrafficSource.FINDINGS,
                    TrafficSource.EXTENSIONS);
            assertEquals(List.of(TrafficSource.PROXY, TrafficSource.SITE_MAP, TrafficSource.FINDINGS,
                            TrafficSource.EXTENSIONS),
                    catalog.stream(enabled, "User").map(CapturedEntry::source).toList());
            var filters = TrafficFilters.create("app.example.test", false, true, false, false,
                    "POST", "2xx", "json", ".json", "");
            assertEquals(3, catalog.stream(enabled, "User").filter(filters::matches).count());
            var listenerFilter = TrafficFilters.create("", false, true, false, true,
                    "GET", "200", "", "", "8080");
            assertEquals(1, catalog.stream(enabled, "User").filter(listenerFilter::matches).count());
            var records = catalog.stream(Set.of(TrafficSource.SCANNER, TrafficSource.PROXY), "User").toList();
            var results = new ArrayList<ResultRow>();
            var engine = new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(results));
            engine.runText(TimedRegex.compile("remote\\s+response"), true, true);
            assertEquals(1, results.size());
            assertEquals(TrafficSource.PROXY, results.get(0).entry.source());
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void interruptedArchiveTransferKeepsExistingExport(@TempDir Path directory) throws Exception {
        var archive = directory.resolve("preserved.tsv");
        Files.writeString(archive, "Existing archive contents");

        Thread.currentThread().interrupt();
        try {
            assertThrows(java.io.InterruptedIOException.class, () -> Persistence.exportArchive(archive, List.of()));
            assertThrows(java.io.InterruptedIOException.class, () -> Persistence.importArchive(archive));
        } finally {
            Thread.interrupted();
        }

        assertEquals("Existing archive contents", Files.readString(archive));
    }

    @Test
    void importsLoggerCsvAndPreservesToolAttributionAcrossArchiveTransfer(@TempDir Path directory) throws Exception {
        String raw = "POST /logged HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nvalue, \"a\"";
        String resp = java.util.Base64.getEncoder().encodeToString(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\narchived".getBytes(StandardCharsets.UTF_8));
        Path csv = directory.resolve("logger.csv");
        Files.writeString(csv, "Tool,URL,Request,Response,Comment\nExtensions,https://app.example.test/logged,\""
                + raw.replace("\"", "\"\"") + "\"," + resp + ",reviewed\n");
        var records = Persistence.importArchive(csv);
        assertEquals(1, records.size());
        assertEquals(TrafficSource.EXTENSIONS, records.get(0).source());
        assertTrue(records.get(0).annotated());
        assertEquals("value, \"a\"", Util.requestText(records.get(0).requestResponse()).body());
        var exported = directory.resolve("archive.tsv");
        Persistence.exportArchive(exported, records);
        assertEquals(TrafficSource.EXTENSIONS, Persistence.importArchive(exported).get(0).source());
        assertEquals("archived", Util.responseText(Persistence.importArchive(exported).get(0).requestResponse()).body());
    }

    @Test
    void scansFiveThousandMixedFormatRecords() {
        var first = exchange(request("POST", "/send", "{\"userId\":\"" + USER + "\"}",
                "application/json", Map.of(), HOST), response("<root><ref>" + USER + "</ref></root>",
                "application/xml", Map.of()));
        var second = exchange(request("POST", "/send", "userId=" + USER, "application/x-www-form-urlencoded",
                Map.of(), HOST), response("const ref = '" + USER + "';", "text/javascript", Map.of()));
        var records = java.util.stream.IntStream.range(0, 5_000)
                .mapToObj(i -> CapturedEntry.of("", i % 2 == 0 ? first : second, TIME + i)).toList();
        var results = new ArrayList<ResultRow>();
        var clock = java.lang.management.ManagementFactory.getThreadMXBean();
        long wallStart = System.nanoTime();
        long cpuStart = clock.getCurrentThreadCpuTime();
        new ExtractEngine(records, "", 0, false, ExtractEngine.Direction.BOTH, false, false, sink(results))
                .runValue(USER, Set.of());
        assertEquals(10_000, results.size());
        System.out.printf("Synthetic mixed-format search, 5,000 records: %.0f ms elapsed, %.0f ms thread CPU%n",
                (System.nanoTime() - wallStart) / 1_000_000.0, (clock.getCurrentThreadCpuTime() - cpuStart) / 1_000_000.0);
    }

    @Test
    void rendersArchiveTabAndControlsOffscreen() throws Exception {
        var store = new CollectorStore(persistence());
        var api = mock(MontoyaApi.class, (name, args) -> offscreenUi());
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var menu = new SearchContextMenu(api, store, CaptureProfile::defaults, config -> {});
                var tab = new CollectorTab(api, store, menu, CaptureProfile::defaults, config -> {});
                try {
                    var component = (javax.swing.JComponent) tab.uiComponent();
                    assertFalse(button(component, "Export archive…").isEnabled());
                    assertTrue(button(component, "Search all traffic…").isEnabled());
                    assertTrue(button(component, "Label history…").isEnabled());
                    assertTrue(button(component, "Project settings…").isEnabled());
                    assertTrue(button(component, "Trace a cookie…").isEnabled());
                    assertTrue(button(component, "Info").isEnabled());
                    assertEquals("v1.0.1", BuildInfo.release());
                    render(component, 1050, 700, "archive");
                } finally {
                    tab.close();
                    menu.close();
                }
            });
        } finally {
            store.flushAndShutdown();
        }
    }

    @Test
    void logoutFieldsExposeDefaultsAndRespectTheDialogEditState() throws Exception {
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            var logout = new LogoutFields(false);
            logout.setRule(LogoutRule.NONE);
            var rows = logout.rows("Logout response body regex", true);
            var form = Dialogs.stack(7, rows.toArray(javax.swing.JComponent[]::new));
            var path = find(rows.get(0), javax.swing.JTextField.class);
            var method = find(rows.get(1), javax.swing.JTextField.class);
            var statuses = find(rows.get(2), javax.swing.JTextField.class);
            assertFalse(method.isEnabled());
            assertEquals("2xx, 3xx", statuses.getText());
            path.setText("^/logout$");
            method.setText("post");
            assertTrue(method.isEnabled());
            assertEquals(new LogoutRule("^/logout$", "POST", "", "", ""),
                    logout.read(java.util.function.UnaryOperator.identity()));
            for (var row : rows) {
                assertSame(find(row, javax.swing.JTextField.class), find(row, javax.swing.JLabel.class).getLabelFor());
            }
            logout.setEditable(false);
            assertFalse(path.isEnabled());
            assertFalse(method.isEnabled());
            logout.setEditable(true);
            assertTrue(statuses.isEnabled());
            render(form, 500, form.getPreferredSize().height, "logout-fields");
            path.setText("");
            assertFalse(statuses.isEnabled());
            assertEquals(LogoutRule.NONE, logout.read(java.util.function.UnaryOperator.identity()));
        });
    }

    @Test
    void searchAndInfoLayoutsKeepControlsSeparatedAtNarrowWidths() throws Exception {
        var store = new CollectorStore(persistence());
        var scans = new ScanQueue();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var api = mock(MontoyaApi.class, (name, args) -> offscreenUi());
                var search = new SearchPanel(api, store, scans, CaptureProfile::defaults,
                        ExtractDialog.Dataset.ALL, ExtractDialog.Context.empty(), () -> {});
                try {
                    render(search, 760, 500, "search-narrow");
                    var query = find(search, javax.swing.JTextField.class);
                    var searchButton = button(search, "Browse traffic");
                    var clear = button(search, "Clear");
                    assertNotNull(query);
                    assertNotNull(searchButton);
                    assertNotNull(clear);
                    assertTrue(hasComboSelection(search, "All matches"));
                    var q = javax.swing.SwingUtilities.convertRectangle(query.getParent(), query.getBounds(), search);
                    var submit = javax.swing.SwingUtilities.convertRectangle(searchButton.getParent(), searchButton.getBounds(), search);
                    var reset = javax.swing.SwingUtilities.convertRectangle(clear.getParent(), clear.getBounds(), search);
                    assertTrue(q.width > 220);
                    assertTrue(submit.x - (q.x + q.width) >= 10);
                    assertTrue(reset.x - (submit.x + submit.width) >= 6);
                    var sources = find(search, SourcePicker.class);
                    var sourceBounds = javax.swing.SwingUtilities.convertRectangle(sources.getParent(), sources.getBounds(), search);
                    assertTrue(sourceBounds.y - (q.y + q.height) >= 10);
                    var host = find(search, javax.swing.JCheckBox.class, box -> box.getText().equals("Same host"));
                    var hostBounds = javax.swing.SwingUtilities.convertRectangle(host.getParent(), host.getBounds(), search);
                    assertEquals(sourceBounds.y, hostBounds.y, 4);
                    var advanced = find(search, javax.swing.JToggleButton.class, button -> button.getText().equals("Advanced"));
                    advanced.doClick();
                    render(search, 760, 500, "search-advanced");
                    var panes = find(search, javax.swing.JSplitPane.class);
                    assertTrue(panes.getHeight() > 100);

                    var info = BuildInfo.content(() -> {});
                    var preferred = info.getPreferredSize();
                    render(info, preferred.width, preferred.height, "info");
                    assertTrue(hasLabel(info, "WhileEndless"));
                    assertTrue(hasLabel(info, "http-traffic-workbench"));
                    assertTrue(hasLabel(info, "Version v1.0.1"));
                    assertNotNull(button(info, "Open repository"));
                    assertNotNull(button(info, "Copy repository URL"));

                    var popup = sources.getComponentPopupMenu();
                    var popupSize = popup.getPreferredSize();
                    render(popup, popupSize.width, popupSize.height, "source-menu");
                    assertNotNull(button(popup, "All"));
                    assertNotNull(button(popup, "None"));
                    advanced.doClick();
                    enlargeFonts(search);
                    render(search, 960, 620, "search-large-text");
                    var largeQuery = javax.swing.SwingUtilities.convertRectangle(query.getParent(), query.getBounds(), search);
                    var largeSearch = javax.swing.SwingUtilities.convertRectangle(searchButton.getParent(),
                            searchButton.getBounds(), search);
                    assertTrue(largeSearch.x - (largeQuery.x + largeQuery.width) >= 10);
                    assertTrue(largeSearch.x + largeSearch.width < 960);
                } finally {
                    search.close();
                }
            });
        } finally {
            scans.close();
            store.flushAndShutdown();
        }
    }

    private static void enlargeFonts(java.awt.Component component) {
        var font = component.getFont();
        if (font != null) component.setFont(font.deriveFont(font.getSize2D() * 1.25f));
        if (component instanceof java.awt.Container container) {
            for (var child : container.getComponents()) enlargeFonts(child);
        }
    }

    private static boolean hasComboSelection(java.awt.Container parent, String value) {
        for (var child : parent.getComponents()) {
            if (child instanceof javax.swing.JComboBox<?> combo && combo.getSelectedItem() != null
                    && value.equals(combo.getSelectedItem().toString())) return true;
            if (child instanceof java.awt.Container container && hasComboSelection(container, value)) return true;
        }
        return false;
    }

    private static boolean hasLabel(java.awt.Container parent, String text) {
        for (var child : parent.getComponents()) {
            if (child instanceof javax.swing.JLabel label && text.equals(label.getText())) return true;
            if (child instanceof java.awt.Container container && hasLabel(container, text)) return true;
        }
        return false;
    }

    private static burp.api.montoya.ui.UserInterface offscreenUi() {
        return offscreenUi(ignored -> {});
    }

    private static burp.api.montoya.ui.UserInterface offscreenUi(java.util.function.Consumer<String> search) {
        var request = mock(burp.api.montoya.ui.editor.HttpRequestEditor.class,
                (name, args) -> {
                    if (name.equals("setSearchExpression")) search.accept((String) args[0]);
                    return name.equals("uiComponent") ? new javax.swing.JPanel() : null;
                });
        var response = mock(burp.api.montoya.ui.editor.HttpResponseEditor.class,
                (name, args) -> {
                    if (name.equals("setSearchExpression")) search.accept((String) args[0]);
                    return name.equals("uiComponent") ? new javax.swing.JPanel() : null;
                });
        return mock(burp.api.montoya.ui.UserInterface.class, (name, args) -> switch (name) {
            case "createHttpRequestEditor" -> request;
            case "createHttpResponseEditor" -> response;
            default -> null;
        });
    }

    private static <T extends java.awt.Component> T find(java.awt.Container root, Class<T> type) {
        return find(root, type, component -> true);
    }

    private static <T extends java.awt.Component> T find(java.awt.Container root, Class<T> type,
                                                          java.util.function.Predicate<T> filter) {
        for (var child : root.getComponents()) {
            if (type.isInstance(child) && filter.test(type.cast(child))) return type.cast(child);
            if (child instanceof java.awt.Container nested) {
                T match = find(nested, type, filter);
                if (match != null) return match;
            }
        }
        return null;
    }

    private static javax.swing.JButton button(java.awt.Container root, String label) {
        for (var child : root.getComponents()) {
            if (child instanceof javax.swing.JButton item && item.getText().equals(label)) return item;
            if (child instanceof java.awt.Container container) {
                var result = button(container, label);
                if (result != null) return result;
            }
        }
        return null;
    }

    private static void render(java.awt.Container panel, int width, int height, String name) {
        panel.setSize(width, height);
        layout(panel);
        var image = new java.awt.image.BufferedImage(width, height, java.awt.image.BufferedImage.TYPE_INT_RGB);
        var graphics = image.createGraphics();
        try {
            panel.printAll(graphics);
            var folder = Path.of("target", "ui-smoke");
            Files.createDirectories(folder);
            javax.imageio.ImageIO.write(image, "png", folder.resolve(name + ".png").toFile());
        } catch (java.io.IOException ex) {
            throw new java.io.UncheckedIOException(ex);
        } finally {
            graphics.dispose();
        }
    }

    private static void layout(java.awt.Container container) {
        container.doLayout();
        for (var child : container.getComponents()) {
            if (child instanceof java.awt.Container nested) layout(nested);
        }
    }

    private static CaptureProfile profile(CaptureProfile.Source source, String field) {
        return profile(source, field, Set.of());
    }

    private static CaptureProfile profile(CaptureProfile.Source source, String field, Set<TrafficSource> tools) {
        return profile(source, field, tools, new LogoutRule("^/logout$", "", "any", "", ""));
    }

    private static CaptureProfile profile(CaptureProfile.Source source, String field, Set<TrafficSource> tools, LogoutRule logout) {
        return new CaptureProfile(true, true, false, HOST, "", true, source,
                CaptureProfile.Locator.FIELD, field, "User", COOKIE, logout,
                "^/login$", "POST", "", false, 30, tools);
    }

    private static List<String> values(String body, String type, String key) {
        return FieldExtractor.pairs(body, type, null, StandardCharsets.UTF_8).stream()
                .filter(pair -> key.equals(pair.key) && !pair.value.isEmpty()).map(pair -> pair.value).toList();
    }

    private static ExtractEngine.Sink sink(List<ResultRow> rows) {
        return new ExtractEngine.Sink() {
            @Override public void row(ResultRow row) { rows.add(row); }
            @Override public void progress(String phase, int done, int total) {}
            @Override public boolean cancelled() { return false; }
        };
    }

    private static ProxyHttpRequestResponse history(String method, String path, String cookie, String label,
                                                       String notes, long time, String host) {
        return history(method, path, cookie, label, notes, time, host, label == null ? null : "sid=s1; Path=/");
    }

    private static ProxyHttpRequestResponse history(String method, String path, String cookie, String label,
                                                       String notes, long time, String host, String setCookie) {
        var request = request(method, path, "", null, cookie.isEmpty() ? Map.of() : Map.of(COOKIE, cookie), host);
        var response = response(label == null ? "" : "{\"userId\":\"" + label + "\"}", "application/json",
                setCookie == null ? Map.of() : Map.of("Set-Cookie", setCookie));
        return history(request, response, notes, time);
    }

    private static ProxyHttpRequestResponse logoutExchange(String method, String body, int status, boolean confirmed, long time) {
        var request = request(method, "/action?source=test", body, "application/x-www-form-urlencoded", Map.of(COOKIE, "s1"), HOST);
        var response = status == 0 ? null : response(("{\"loggedOut\":" + confirmed + "}").getBytes(StandardCharsets.UTF_8),
                "application/json", Map.of("Set-Cookie", "sid=s1; Path=/"), status);
        return history(request, response, "", time);
    }

    private static ProxyHttpRequestResponse history(HttpRequest request, HttpResponse response, String notes, long time) {
        var annotations = annotations(notes);
        return mock(ProxyHttpRequestResponse.class, (name, args) -> switch (name) {
            case "request", "finalRequest" -> request;
            case "response" -> response;
            case "annotations" -> annotations;
            case "listenerPort" -> 8080;
            case "timingData" -> mock(burp.api.montoya.http.handler.TimingData.class, (methodName, unused) ->
                    Instant.ofEpochMilli(time).atZone(ZoneOffset.UTC));
            case "time" -> Instant.ofEpochMilli(time).atZone(ZoneOffset.UTC);
            default -> null;
        });
    }

    private static Persistence persistence() {
        Map<Object, Object> data = new HashMap<>();
        var project = mock(PersistedObject.class, (name, args) -> switch (name) {
            case "setString", "setByteArray" -> data.put(args[0], args[1]);
            case "getString", "getByteArray" -> data.get(args[0]);
            case "deleteByteArray" -> data.remove(args[0]);
            default -> null;
        });
        var persistence = mock(burp.api.montoya.persistence.Persistence.class, (name, args) -> project);
        return new Persistence(mock(MontoyaApi.class, (name, args) -> persistence));
    }

    private static Annotations annotations(String start) {
        var notes = new AtomicReference<>(start);
        return mock(Annotations.class, (name, args) -> switch (name) {
            case "notes" -> notes.get();
            case "hasHighlightColor" -> false;
            case "setNotes" -> notes.getAndSet((String) args[0]);
            case "withNotes" -> annotations((String) args[0]);
            default -> null;
        });
    }

    private static HttpRequestResponse exchange(HttpRequest request, HttpResponse response) {
        return mock(HttpRequestResponse.class, (name, args) -> switch (name) {
            case "request" -> request;
            case "response" -> response;
            default -> null;
        });
    }

    private static HttpService service(String host, int port, boolean secure) {
        return mock(HttpService.class, (name, args) -> switch (name) {
            case "host" -> host;
            case "port" -> port;
            case "secure" -> secure;
            default -> null;
        });
    }

    private static HttpRequest request(String method, String path, String body, String type, Map<String, String> cookies, String host) {
        var requestHeaders = new LinkedHashMap<String, String>();
        if (type != null) requestHeaders.put("Content-Type", type);
        if (!cookies.isEmpty()) {
            requestHeaders.put("Cookie", cookies.entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue()).collect(java.util.stream.Collectors.joining("; ")));
        }
        String raw = method + " " + path + " HTTP/1.1\r\n" + headerText(requestHeaders) + "\r\n" + body;
        return requestFrom(service(host, 443, true), bytes(raw.getBytes(StandardCharsets.UTF_8)));
    }

    private static HttpRequest requestFrom(HttpService service, ByteArray rawBytes) {
        String raw = new String(rawBytes.getBytes(), StandardCharsets.UTF_8);
        String[] parts = raw.split("\r\n\r\n", 2);
        String[] line = parts[0].split("\r\n", 2)[0].split(" ");
        String[] path = line[1].split("\\?", 2);
        var headers = headerMap(parts[0]);
        var body = bytes((parts.length > 1 ? parts[1] : "").getBytes(StandardCharsets.UTF_8));
        return mock(HttpRequest.class, (name, args) -> switch (name) {
            case "httpService" -> service;
            case "method" -> line[0];
            case "path" -> line[1];
            case "pathWithoutQuery" -> path[0];
            case "query" -> path.length == 2 ? path[1] : null;
            case "url" -> "https://" + service.host() + line[1];
            case "isInScope" -> true;
            case "fileExtension" -> path[0].lastIndexOf('.') > path[0].lastIndexOf('/')
                    ? path[0].substring(path[0].lastIndexOf('.') + 1) : "";
            case "headers" -> headers(headers);
            case "headerValue" -> headers.get(args[0]);
            case "body" -> body;
            case "toByteArray" -> rawBytes;
            default -> null;
        });
    }

    private static HttpResponse response(String content, String type, Map<String, String> extra) {
        return response(content.getBytes(StandardCharsets.UTF_8), type, extra);
    }

    private static HttpResponse response(byte[] content, String type, Map<String, String> extra) {
        return response(content, type, extra, 200);
    }

    private static HttpResponse response(byte[] content, String type, Map<String, String> extra, int status) {
        Map<String, String> headers = new LinkedHashMap<>(extra);
        if (type != null) headers.put("Content-Type", type);
        byte[] prefix = ("HTTP/1.1 " + status + " Status\r\n" + headerText(headers) + "\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] raw = Arrays.copyOf(prefix, prefix.length + content.length);
        System.arraycopy(content, 0, raw, prefix.length, content.length);
        return responseFrom(bytes(raw));
    }

    private static HttpResponse responseFrom(ByteArray raw) {
        byte[] content = raw.getBytes();
        String full = new String(content, StandardCharsets.ISO_8859_1);
        short status = Short.parseShort(full.substring(9, 12));
        int index = full.indexOf("\r\n\r\n");
        var map = headerMap(full.substring(0, index));
        var body = bytes(Arrays.copyOfRange(content, index + 4, content.length));
        return mock(HttpResponse.class, (name, args) -> switch (name) {
            case "headers" -> headers(map);
            case "headerValue" -> map.get(args[0]);
            case "statusCode" -> status;
            case "body" -> body;
            case "toByteArray" -> raw;
            default -> null;
        });
    }

    private static List<HttpHeader> headers(Map<String, String> values) {
        return values.entrySet().stream().map(entry -> mock(HttpHeader.class,
                (name, args) -> name.equals("name") ? entry.getKey() : entry.getValue())).toList();
    }

    private static Map<String, String> headerMap(String prefix) {
        Map<String, String> result = new LinkedHashMap<>();
        prefix.lines().skip(1).filter(line -> line.contains(":")).forEach(line -> {
            int separator = line.indexOf(':');
            result.put(line.substring(0, separator), line.substring(separator + 1).strip());
        });
        return result;
    }

    private static String headerText(Map<String, String> headers) {
        return headers.entrySet().stream().map(entry -> entry.getKey() + ": " + entry.getValue() + "\r\n")
                .collect(java.util.stream.Collectors.joining());
    }

    private static ByteArray bytes(byte[] value) {
        return mock(ByteArray.class, (name, args) -> switch (name) {
            case "length" -> value.length;
            case "getBytes" -> value;
            case "subArray" -> bytes(Arrays.copyOfRange(value, (int) args[0], (int) args[1]));
            default -> null;
        });
    }

    private static <T> T mock(Class<T> type, Call call) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (target, method, args) -> {
            return switch (method.getName()) {
                case "hashCode" -> System.identityHashCode(target);
                case "equals" -> target == args[0];
                case "toString" -> type.getSimpleName();
                default -> call.invoke(method.getName(), args);
            };
        }));
    }

    @FunctionalInterface
    private interface Call {
        Object invoke(String method, Object[] args);
    }
}
