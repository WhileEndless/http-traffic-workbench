package trafficworkbench;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

final class HttpSearchFields {
    private static final int MAX_HEADER_FIELDS = 256;
    private static final int MAX_HEADER_VALUE = 4_096;

    private static final Pattern PRIVATE_HEADER = Pattern.compile(
            "authorization|credential|password|api[-_]?key|(?:^|-)token(?:-|$)|(?:^|-)secret(?:-|$)");

    private HttpSearchFields() {}

    static List<FieldExtractor.Pair> collect(HttpRequestResponse exchange, boolean request) {
        var text = request ? Util.requestText(exchange) : Util.responseText(exchange);
        return collect(request ? exchange.request() : exchange.response(), !request, text.searchFields());
    }

    static List<FieldExtractor.Pair> collect(HttpMessage message, boolean response, List<FieldExtractor.Pair> body) {
        if (message == null) return body;
        var headers = message.headers();
        if (headers.isEmpty()) return body;
        var fields = new ArrayList<FieldExtractor.Pair>(body.size() + Math.min(headers.size(), MAX_HEADER_FIELDS));
        fields.addAll(body);
        int maximum = body.size() + MAX_HEADER_FIELDS;
        for (var header : headers) {
            if (fields.size() >= maximum) break;
            String name = header.name();
            if (name.equalsIgnoreCase("Cookie") || name.equalsIgnoreCase("Set-Cookie")) continue;
            String value = header.value().strip();
            if (value.length() <= MAX_HEADER_VALUE) {
                fields.add(new FieldExtractor.Pair(name, value, -1, FieldExtractor.Kind.HEADER));
            }
        }
        Cookies.read(headers, response, null, field -> {
            if (fields.size() < maximum) {
                fields.add(new FieldExtractor.Pair(field.name(), field.value(), -1, FieldExtractor.Kind.COOKIE));
            }
        });
        return fields;
    }

    static boolean protectedValue(FieldExtractor.Pair field) {
        return field.kind == FieldExtractor.Kind.COOKIE || field.kind == FieldExtractor.Kind.HEADER && protectedHeader(field.key);
    }

    static boolean indexForDiscovery(FieldExtractor.Pair field, boolean protectedValue) {
        if (protectedValue || field.domId) return false;
        if (field.kind != FieldExtractor.Kind.HEADER) return true;
        return switch (field.key.toLowerCase(Locale.ROOT)) {
            case "accept", "accept-encoding", "accept-language", "cache-control", "connection", "content-length",
                    "content-type", "date", "host", "referer", "server", "user-agent" -> false;
            default -> true;
        };
    }

    static boolean protectedHeader(String name) {
        return name.equalsIgnoreCase("Cookie") || name.equalsIgnoreCase("Set-Cookie")
                || PRIVATE_HEADER.matcher(name.toLowerCase(Locale.ROOT)).find();
    }
}
