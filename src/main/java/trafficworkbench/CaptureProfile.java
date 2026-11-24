package trafficworkbench;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpMessage;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.regex.Pattern;

record CaptureProfile(boolean collect, boolean persistArchive, boolean inScope, String hosts,
                      String path, boolean annotate, Source source, Locator locator,
                      String expression, String notePrefix, String sessionCookie, LogoutRule logout,
                      String identityPath, String identityMethod, String identityRequestBody, boolean successfulOnly, int sessionMinutes,
                      Set<TrafficSource> captureTools) {
    CaptureProfile {
        captureTools = Set.copyOf(captureTools);
    }

    enum Source {
        REQUEST("Request"), RESPONSE("Response"), REQUEST_FIRST("Request first, then response"),
        RESPONSE_FIRST("Response first, then request");

        private final String label;
        Source(String label) { this.label = label; }
        public String toString() { return label; }
    }

    enum Locator {
        FIELD("Field name"), HEADER("HTTP header"), REGEX("Body regex (first group)");

        private final String label;
        Locator(String label) { this.label = label; }
        public String toString() { return label; }
    }

    static CaptureProfile defaults() {
        return new CaptureProfile(false, false, true, "", "", false,
                Source.RESPONSE_FIRST, Locator.FIELD, "", "User", "", LogoutRule.NONE, "", "", "", false, 30, Set.of());
    }

    Compiled compile() {
        Set<String> hostSet = Arrays.stream(hosts.split("[,\\s]+"))
                .filter(host -> !host.isEmpty())
                .map(host -> host.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        if (hostSet.stream().anyMatch(host -> !host.matches("[a-z0-9_.:-]+"))) {
            throw new IllegalArgumentException("Enter comma-separated hostnames or IP addresses.");
        }
        if ((collect || annotate || !captureTools.isEmpty()) && !inScope && hostSet.isEmpty()) {
            throw new IllegalArgumentException("Use Burp scope or enter a host to capture or label traffic.");
        }
        if (annotate && expression.isBlank()) {
            throw new IllegalArgumentException("Enter a user identifier field, header, or regex to add notes.");
        }
        if (!sessionCookie.isBlank() && (expression.isBlank() || !Cookies.validName(sessionCookie))) {
            throw new IllegalArgumentException("Enter a cookie name and a user identifier field, header, or regex.");
        }
        if (!logout.path().isEmpty() && sessionCookie.isBlank()) {
            throw new IllegalArgumentException("Enter a session cookie name to use a logout rule.");
        }
        if (notePrefix.isBlank() || notePrefix.contains("\n") || notePrefix.contains("\r") || notePrefix.length() > 80) {
            throw new IllegalArgumentException("Use a single line of up to 80 characters for the note prefix.");
        }
        Pattern selector = locator == Locator.REGEX && !expression.isBlank()
                ? pattern(expression, "User identifier regex") : null;
        if (selector != null && selector.matcher("").groupCount() == 0) {
            throw new IllegalArgumentException("Use a capture group for the user identifier in the regex.");
        }
        if (locator == Locator.HEADER && !expression.isBlank() && !expression.matches("[A-Za-z0-9!#$%&'*+.^_`|~-]+")) {
            throw new IllegalArgumentException("Enter a valid HTTP header name.");
        }
        if (sessionMinutes < 0 || sessionMinutes > 1440) {
            throw new IllegalArgumentException("Enter a session timeout from 0 to 1,440 minutes.");
        }
        if (captureTools.stream().anyMatch(source -> !source.toolTraffic())) {
            throw new IllegalArgumentException("Select a Burp tool for live capture.");
        }
        if (!identityMethod.isEmpty() && !identityMethod.matches("[A-Z][A-Z0-9_-]{0,19}")) {
            throw new IllegalArgumentException("Enter an uppercase HTTP method such as POST.");
        }
        return new Compiled(this, hostSet, pattern(path, "Request path"), selector,
                logout.compile(), pattern(identityPath, "User identifier extraction path"),
                pattern(identityRequestBody, "Login request body"));
    }

    private static Pattern pattern(String expression, String field) {
        try {
            return expression.isEmpty() ? null : TimedRegex.compile(expression);
        } catch (java.util.regex.PatternSyntaxException ex) {
            throw new IllegalArgumentException(field + " is invalid. " + ex.getDescription());
        }
    }

    String encode() throws IOException {
        Properties data = new Properties();
        data.setProperty("version", "2");
        data.setProperty("captureTools", captureTools.stream().map(Enum::name).sorted()
                .collect(Collectors.joining(",")));
        data.setProperty("collect", Boolean.toString(collect));
        data.setProperty("persistArchive", Boolean.toString(persistArchive));
        data.setProperty("inScope", Boolean.toString(inScope));
        data.setProperty("hosts", hosts);
        data.setProperty("path", path);
        data.setProperty("annotate", Boolean.toString(annotate));
        data.setProperty("source", source.name());
        data.setProperty("locator", locator.name());
        data.setProperty("expression", expression);
        data.setProperty("notePrefix", notePrefix);
        data.setProperty("sessionCookie", sessionCookie);
        data.setProperty("endPath", logout.path());
        data.setProperty("endMethod", logout.method());
        data.setProperty("endStatuses", logout.statuses());
        data.setProperty("endRequestBody", logout.requestBody());
        data.setProperty("endResponseBody", logout.responseBody());
        data.setProperty("identityPath", identityPath);
        data.setProperty("identityMethod", identityMethod);
        data.setProperty("identityRequestBody", identityRequestBody);
        data.setProperty("sessionMinutes", Integer.toString(sessionMinutes));
        data.setProperty("successfulOnly", Boolean.toString(successfulOnly));
        var output = new StringWriter();
        data.store(output, "HTTP Traffic Workbench project profile");
        return output.toString();
    }

    static CaptureProfile decode(String text) throws IOException {
        if (text == null) {
            return defaults();
        }
        Properties data = new Properties();
        try {
            data.load(new StringReader(text));
            String version = data.getProperty("version");
            boolean legacy = "1".equals(version);
            if (!legacy && !"2".equals(version)) {
                throw new IllegalArgumentException("This profile format or version is unsupported.");
            }
            String endPath = property(data, "endPath");
            String cookie = property(data, "sessionCookie");
            LogoutRule logout;
            if (legacy) {
                logout = endPath.isEmpty() || cookie.isBlank() ? LogoutRule.NONE : new LogoutRule(endPath, "", "any", "", "");
            } else {
                logout = new LogoutRule(endPath, property(data, "endMethod"), property(data, "endStatuses"),
                        property(data, "endRequestBody"), property(data, "endResponseBody"));
            }
            var profile = new CaptureProfile(bool(data, "collect"), bool(data, "persistArchive"),
                    bool(data, "inScope"), property(data, "hosts"), property(data, "path"),
                    bool(data, "annotate"), Source.valueOf(property(data, "source")),
                    Locator.valueOf(property(data, "locator")), property(data, "expression"),
                    property(data, "notePrefix"), cookie, logout,
                    property(data, "identityPath"), property(data, "identityMethod"),
                    legacy ? "" : property(data, "identityRequestBody"), bool(data, "successfulOnly"),
                    Integer.parseInt(property(data, "sessionMinutes")),
                    Arrays.stream(data.getProperty("captureTools", "").split(",")).filter(value -> !value.isBlank())
                            .map(TrafficSource::valueOf).collect(Collectors.toSet()));
            profile.compile();
            return profile;
        } catch (IllegalArgumentException ex) {
            throw new IOException("Could not read the profile. " + ex.getMessage(), ex);
        }
    }

    private static boolean bool(Properties data, String key) {
        String value = property(data, key);
        if (!value.equals("true") && !value.equals("false")) {
            throw new IllegalArgumentException("Invalid setting " + key);
        }
        return Boolean.parseBoolean(value);
    }

    private static String property(Properties data, String key) {
        String value = data.getProperty(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing setting " + key);
        }
        return value;
    }

    record Compiled(CaptureProfile settings, Set<String> hosts, Pattern path, Pattern selector,
                    LogoutRule.Compiled logout, Pattern identityPath, Pattern identityRequestBody) {
        boolean covers(HttpRequest request) {
            return request.httpService() != null
                    && (!settings.inScope || request.isInScope())
                    && (hosts.isEmpty() || hosts.contains(request.httpService().host().toLowerCase(Locale.ROOT)));
        }

        boolean matches(HttpRequest request) {
            return covers(request) && includesPath(request);
        }

        boolean includesPath(HttpRequest request) {
            return path == null || TimedRegex.finds(path, request.pathWithoutQuery());
        }

        boolean hasExplicitStart() {
            return identityPath != null || !settings.identityMethod.isEmpty() || identityRequestBody != null;
        }

        boolean canIdentify(HttpRequest request, int limit) {
            return (settings.identityMethod.isEmpty() || settings.identityMethod.equals(request.method()))
                    && (identityPath == null || TimedRegex.finds(identityPath, request.pathWithoutQuery()))
                    && (identityRequestBody == null
                        || TimedRegex.finds(identityRequestBody, Util.text(request, null, limit).body()));
        }

        String identify(HttpMessage message, String query, int limit) {
            if (message == null || settings.expression.isEmpty()) {
                return "";
            }
            if (settings.locator == Locator.HEADER) {
                return clean(message.headerValue(settings.expression));
            }
            return identify(Util.text(message, query, limit));
        }

        String identify(Util.MessageText message) {
            if (message == null || settings.expression.isEmpty()) {
                return "";
            }
            if (selector != null) {
                return clean(TimedRegex.group(selector, message.body()));
            }
            return FieldExtractor.identifier(message.fields(), settings.expression);
        }

        private String clean(String value) {
            String text = Objects.toString(value, "").strip();
            return text.length() > 256 || text.chars().anyMatch(Character::isISOControl) ? "" : text;
        }
    }
}
