package trafficworkbench;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

record SessionSuggestions(List<FieldExtractor.Pair> requestFields, List<FieldExtractor.Pair> responseFields,
                          List<String> requestCookies, List<String> responseCookies, boolean hasResponse) {
    static SessionSuggestions read(HttpRequestResponse exchange) {
        return new SessionSuggestions(Util.requestText(exchange).fields(), Util.responseText(exchange).fields(),
                cookieNames(exchange.request(), false), cookieNames(exchange.response(), true), exchange.response() != null);
    }

    List<String> fields(CaptureProfile.Source source) {
        var names = new LinkedHashSet<String>();
        if (source != CaptureProfile.Source.RESPONSE) names.addAll(names(requestFields));
        if (source != CaptureProfile.Source.REQUEST) names.addAll(names(responseFields));
        return names.stream().sorted(Comparator.comparingInt(SessionSuggestions::rank)).limit(200).toList();
    }

    String cookieLocation(String cookie) {
        boolean request = requestCookies.contains(cookie);
        boolean response = responseCookies.contains(cookie);
        if (response && request) return "Present in request Cookie and response Set-Cookie.";
        if (response) return "Set by the response.";
        if (request) return "Sent in the request.";
        return cookie.isBlank() ? "Choose a cookie name." : "This cookie does not appear in the selected exchange.";
    }

    List<String> cookies() {
        var names = new LinkedHashSet<>(responseCookies);
        names.addAll(requestCookies);
        return names.stream().limit(200).toList();
    }

    String recommendCookie() {
        var all = cookies();
        var recognized = all.stream().filter(name -> {
            String normalized = normalize(name);
            return normalized.equals("sid") || normalized.equals("session") || normalized.endsWith("sessionid");
        }).toList();
        if (recognized.size() == 1) return recognized.get(0);
        if (responseCookies.size() == 1) return responseCookies.get(0);
        return all.size() == 1 ? all.get(0) : "";
    }

    String matchingField(CaptureProfile.Source side, String selection) {
        if (selection.isEmpty() || side == null) return "";
        var pairs = side == CaptureProfile.Source.REQUEST ? requestFields : responseFields;
        if (FieldExtractor.isKey(pairs, selection)) return selection;
        var keys = FieldExtractor.keysForValue(pairs, selection);
        return keys.size() == 1 ? keys.iterator().next() : "";
    }

    String value(CaptureProfile.Source source, String field) {
        return switch (source) {
            case REQUEST -> FieldExtractor.identifier(requestFields, field);
            case RESPONSE -> FieldExtractor.identifier(responseFields, field);
            case REQUEST_FIRST -> first(FieldExtractor.identifier(requestFields, field), FieldExtractor.identifier(responseFields, field));
            case RESPONSE_FIRST -> first(FieldExtractor.identifier(responseFields, field), FieldExtractor.identifier(requestFields, field));
        };
    }

    String recommendField(CaptureProfile.Source source) {
        return fields(source).stream().filter(name -> rank(name) < 10 && !value(source, name).isEmpty())
                .findFirst().orElse("");
    }

    private static String first(String primary, String fallback) {
        return primary.isEmpty() ? fallback : primary;
    }

    private static List<String> names(List<FieldExtractor.Pair> pairs) {
        return pairs.stream().map(pair -> pair.key).filter(key -> key.length() <= 128).distinct().toList();
    }

    private static int rank(String name) {
        String normalized = normalize(name);
        if (normalized.equals("userid") || normalized.equals("usercode")) return 0;
        if (normalized.equals("username") || normalized.equals("usernumber")) return 1;
        if (normalized.endsWith("userid") || normalized.endsWith("usercode")) return 2;
        if (normalized.equals("accountid") || normalized.equals("customerid")) return 3;
        return 10;
    }

    private static String normalize(String name) {
        return name.toLowerCase(Locale.ROOT).replace("_", "").replace("-", "");
    }

    private static List<String> cookieNames(HttpMessage message, boolean response) {
        return Cookies.fields(message, response).stream().map(Cookies.Field::name).distinct().toList();
    }
}
