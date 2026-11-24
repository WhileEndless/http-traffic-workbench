package trafficworkbench;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

record LogoutRule(String path, String method, String statuses, String requestBody, String responseBody) {
    static final LogoutRule NONE = new LogoutRule("", "", "", "", "");

    Compiled compile() {
        if (path.isEmpty()) {
            if (!equals(NONE)) throw new IllegalArgumentException("Enter a logout path to use logout conditions.");
            return new Compiled(null, "", Set.of(), null, null);
        }
        if (!method.isEmpty() && !method.matches("[A-Z][A-Z0-9_-]{0,19}")) {
            throw new IllegalArgumentException("Enter a logout HTTP method such as POST.");
        }
        String codes = statuses.toLowerCase(Locale.ROOT);
        Set<String> accepted = codes.equals("any") ? Set.of()
                : codes.isBlank() ? Set.of("2xx", "3xx") : TrafficFilters.statusTokens(codes);
        if (accepted.contains("none") || accepted.isEmpty() && !codes.equals("any")) {
            throw new IllegalArgumentException("Enter logout status codes, families such as 2xx, or any.");
        }
        return new Compiled(pattern(path, "Logout path"), method, accepted,
                pattern(requestBody, "Logout request body"), pattern(responseBody, "Logout response body"));
    }

    private static Pattern pattern(String value, String field) {
        try {
            return value.isEmpty() ? null : TimedRegex.compile(value);
        } catch (PatternSyntaxException ex) {
            throw new IllegalArgumentException(field + " regex is invalid. " + ex.getDescription());
        }
    }

    record Compiled(Pattern path, String method, Set<String> statuses, Pattern requestBody, Pattern responseBody) {
        boolean matchesRequest(HttpRequest request, int limit) {
            return path != null && (method.isEmpty() || method.equals(request.method()))
                    && TimedRegex.finds(path, request.pathWithoutQuery())
                    && (requestBody == null || TimedRegex.finds(requestBody, Util.text(request, null, limit).body()));
        }

        boolean confirms(HttpResponse response, int limit) {
            if (response == null) return statuses.isEmpty() && responseBody == null;
            return (statuses.isEmpty() || TrafficFilters.matchesStatus(statuses, response.statusCode()))
                    && (responseBody == null || TimedRegex.finds(responseBody, Util.text(response, null, limit).body()));
        }
    }
}
