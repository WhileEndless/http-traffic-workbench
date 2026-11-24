package trafficworkbench;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class LoggerCsv {
    private LoggerCsv() {}

    static List<CapturedEntry> read(String data) throws IOException {
        var rows = new Rows(data);
        var columns = new HashMap<String, Integer>();
        var header = rows.next();
        if (header == null) throw new IOException("The Logger CSV is empty.");
        for (int index = 0; index < header.size(); index++) {
            columns.put(header.get(index).toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", ""), index);
        }
        if (!has(columns, "request", "rawrequest", "requestmessage") || !has(columns, "url", "host")) {
            throw new IOException("Logger CSV requires Request and URL or Host columns with raw HTTP data.");
        }
        List<CapturedEntry> result = new ArrayList<>();
        List<String> row;
        int record = 1;
        while ((row = rows.next()) != null) {
            record++;
            try {
                String rawRequest = field(row, columns, "request", "rawrequest", "requestmessage");
                if (rawRequest.isBlank()) continue;
                String url = field(row, columns, "url");
                if (url.isBlank() || !url.contains("://")) {
                    String host = field(row, columns, "host");
                    if (host.isBlank()) host = url;
                    if (!host.contains("://")) {
                        String scheme = field(row, columns, "protocol", "scheme");
                        String tls = field(row, columns, "tls", "secure");
                        boolean secure = scheme.equalsIgnoreCase("https") || tls.equalsIgnoreCase("true")
                                || tls.equalsIgnoreCase("yes");
                        host = (secure ? "https://" : "http://") + host;
                    }
                    url = host;
                }
                URI uri = URI.create(url);
                boolean secure = "https".equalsIgnoreCase(uri.getScheme());
                String portText = field(row, columns, "port");
                int port = uri.getPort() != -1 ? uri.getPort() : !portText.isBlank()
                        ? Integer.parseInt(portText) : secure ? 443 : 80;
                if (uri.getHost() == null || port < 1 || port > 65535) throw new IllegalArgumentException("Invalid service");
                var service = HttpService.httpService(uri.getHost(), port, secure);
                var request = HttpRequest.httpRequest(service, rawBytes(rawRequest, false));
                String rawResponse = field(row, columns, "response", "rawresponse", "responsemessage");
                var response = rawResponse.isBlank() ? null : HttpResponse.httpResponse(rawBytes(rawResponse, true));
                var origin = TrafficSource.fromToolName(field(row, columns, "tool", "toolsource", "source"));
                if (!origin.toolTraffic()) origin = TrafficSource.ARCHIVE;
                String notes = field(row, columns, "comment", "notes");
                String highlight = field(row, columns, "highlight", "highlightcolor");
                long time = timestamp(field(row, columns, "time", "timestamp", "requesttime"));
                result.add(CapturedEntry.of("", HttpRequestResponse.httpRequestResponse(request, response), time,
                        origin, 0, !notes.isBlank() || !highlight.isBlank() && !highlight.equalsIgnoreCase("none")));
            } catch (RuntimeException ex) {
                throw new IOException("Could not read Logger CSV record " + record + ".", ex);
            }
        }
        return result;
    }

    private static ByteArray rawBytes(String value, boolean response) {
        if (value.startsWith("'") && value.length() > 1) value = value.substring(1);
        String firstLine = value.lines().findFirst().orElse("");
        boolean plain = response ? firstLine.startsWith("HTTP/") : firstLine.contains(" HTTP/");
        byte[] data = plain ? value.getBytes(StandardCharsets.UTF_8) : Base64.getDecoder().decode(value.strip());
        return ByteArray.byteArray(data);
    }

    private static long timestamp(String value) {
        if (value.isBlank()) return 0;
        try {
            return Instant.parse(value).toEpochMilli();
        } catch (java.time.format.DateTimeParseException ignored) {
            return 0;
        }
    }

    private static boolean has(Map<String, Integer> columns, String... names) {
        for (String name : names) if (columns.containsKey(name)) return true;
        return false;
    }

    private static String field(List<String> row, Map<String, Integer> columns, String... names) {
        for (String name : names) {
            Integer index = columns.get(name);
            if (index != null && index < row.size()) return row.get(index);
        }
        return "";
    }

    private static final class Rows {
        private final String text;
        private int index;

        private Rows(String text) {
            this.text = text;
            if (text.startsWith("\uFEFF")) index++;
        }

        private List<String> next() throws IOException {
            if (index == text.length()) return null;
            List<String> fields = new ArrayList<>();
            StringBuilder field = new StringBuilder();
            boolean quoted = false;
            while (index < text.length()) {
                if ((index & 4095) == 0) Persistence.checkInterrupted();
                char value = text.charAt(index++);
                if (quoted) {
                    if (value == '"') {
                        if (index < text.length() && text.charAt(index) == '"') {
                            index++;
                            field.append('"');
                        } else {
                            quoted = false;
                        }
                    } else {
                        field.append(value);
                    }
                } else if (value == '"' && field.isEmpty()) {
                    quoted = true;
                } else if (value == ',' || value == '\n' || value == '\r') {
                    fields.add(field.toString());
                    field.setLength(0);
                    if (value != ',') {
                        if (value == '\r' && index < text.length() && text.charAt(index) == '\n') index++;
                        return fields;
                    }
                } else {
                    field.append(value);
                }
            }
            if (quoted) throw new IOException("Unterminated quoted field in Logger CSV.");
            fields.add(field.toString());
            return fields;
        }
    }
}
