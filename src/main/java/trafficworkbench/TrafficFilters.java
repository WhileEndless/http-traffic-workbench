package trafficworkbench;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

record TrafficFilters(String url, boolean inScope, boolean withResponse, boolean withParameters, boolean annotated,
                      Set<String> methods, Set<String> statuses, Set<String> mimeTypes, Set<String> extensions,
                      int listenerPort) {

    static TrafficFilters create(String url, boolean scope, boolean response, boolean parameters, boolean annotated,
                                 String methods, String statuses, String mimeTypes, String extensions, String listener) {
        var status = statusTokens(statuses);
        int port = 0;
        if (!listener.isBlank()) {
            try {
                port = Integer.parseInt(listener.strip());
            } catch (NumberFormatException ignored) {
                port = -1;
            }
            if (port < 1 || port > 65535) throw new IllegalArgumentException("Enter a listener port from 1 to 65535.");
        }
        return new TrafficFilters(url.strip().toLowerCase(Locale.ROOT), scope, response, parameters, annotated,
                tokens(methods), status, tokens(mimeTypes), tokens(extensions).stream().map(value ->
                value.startsWith(".") ? value.substring(1) : value).collect(Collectors.toUnmodifiableSet()), port);
    }

    private static Set<String> tokens(String input) {
        return Arrays.stream(input.toLowerCase(Locale.ROOT).split("[,\\s]+"))
                .filter(value -> !value.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    static Set<String> statusTokens(String input) {
        var statuses = tokens(input);
        if (statuses.stream().anyMatch(value -> !value.matches("[1-5](?:[0-9]{2}|xx)|none"))) {
            throw new IllegalArgumentException("Enter status codes, families such as 2xx, or none.");
        }
        return statuses;
    }

    static boolean matchesStatus(Set<String> statuses, int code) {
        return code == 0 ? statuses.contains("none")
                : statuses.contains(Integer.toString(code)) || statuses.contains(code / 100 + "xx");
    }

    boolean matches(CapturedEntry entry) {
        var request = entry.requestResponse().request();
        var response = entry.requestResponse().response();
        if (inScope && !request.isInScope() || withResponse && response == null
                || withParameters && !request.hasParameters() || annotated && !entry.annotated()
                || listenerPort != 0 && listenerPort != entry.listenerPort()) return false;
        if (!url.isEmpty() && !request.url().toLowerCase(Locale.ROOT).contains(url)) return false;
        if (!methods.isEmpty() && !methods.contains(entry.method().toLowerCase(Locale.ROOT))) return false;
        String extension = extensions.isEmpty() ? "" : request.fileExtension();
        if (!extensions.isEmpty() && !extensions.contains(extension == null || extension.isEmpty()
                ? "none" : extension.toLowerCase(Locale.ROOT))) return false;
        if (!statuses.isEmpty() && !matchesStatus(statuses, entry.statusCode())) return false;
        if (mimeTypes.isEmpty()) return true;
        if (response == null) return mimeTypes.contains("none");
        String header = response.headerValue("Content-Type");
        String type = header == null ? "" : header.split(";", 2)[0].strip().toLowerCase(Locale.ROOT);
        var detected = response.mimeType();
        String name = detected == null ? "" : detected.name().toLowerCase(Locale.ROOT);
        return mimeTypes.stream().anyMatch(filter -> filter.equals("none") && type.isEmpty()
                || !type.isEmpty() && type.contains(filter) || !name.isEmpty() && name.equals(filter));
    }
}
