package trafficworkbench;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpHeader;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.regex.Pattern;

final class Cookies {
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9!#$%&'*+.^_`|~-]+");
    private static final DateTimeFormatter DASHED_DATE =
            DateTimeFormatter.ofPattern("EEE, dd-MMM-uuuu HH:mm:ss z", Locale.US);
    static final int MAX_VALUE_CHARS = 4_096;

    record Field(String name, String value, boolean response, Long maxAge, Long expires) {
        boolean expiredAt(long time) {
            return value.isEmpty() || (maxAge != null ? maxAge <= 0 : expires != null && expires <= time);
        }

        long expiryAt(long time) {
            if (maxAge == null) return expires == null ? Long.MAX_VALUE : expires;
            try {
                return Math.addExact(time, Math.multiplyExact(maxAge, 1_000L));
            } catch (ArithmeticException overflow) {
                return Long.MAX_VALUE;
            }
        }

        @Override public String toString() {
            return name + (response ? " · Response Set-Cookie" : " · Request Cookie");
        }
    }

    private Cookies() {}

    static boolean validName(String name) {
        return name.length() <= 128 && NAME.matcher(name).matches();
    }

    static List<Field> fields(HttpMessage message, boolean response) {
        var fields = new ArrayList<Field>();
        read(message, response, null, fields::add);
        return fields;
    }

    static List<Field> fields(HttpMessage message, boolean response, String name) {
        var fields = new ArrayList<Field>();
        read(message, response, name, fields::add);
        return fields;
    }

    static void read(HttpMessage message, boolean response, String selected, Consumer<Field> use) {
        if (message != null) read(message.headers(), response, selected, use);
    }

    static void read(List<HttpHeader> headers, boolean response, String selected, Consumer<Field> use) {
        for (var header : headers) {
            if (!header.name().equalsIgnoreCase(response ? "Set-Cookie" : "Cookie")) continue;
            String contents = header.value();
            int start = 0;
            while (start < contents.length()) {
                int end = contents.indexOf(';', start);
                if (end < 0) end = contents.length();
                int separator = separator(contents, start, end);
                if (separator >= start && separator < end && end - start <= MAX_VALUE_CHARS + 140) {
                    String name = contents.substring(start, separator).strip();
                    String value = contents.substring(separator + 1, end).strip();
                    if ((selected == null ? validName(name) : selected.equals(name)) && value.length() <= MAX_VALUE_CHARS) {
                        if (response) {
                            use.accept(responseField(name, value, contents, end + 1));
                        } else {
                            use.accept(new Field(name, value, false, null, null));
                        }
                    }
                }
                if (response) break;
                start = end + 1;
            }
        }
    }

    private static Field responseField(String name, String value, String contents, int start) {
        Long maxAge = null;
        Long expires = null;
        for (int position = start; position < contents.length();) {
            int end = contents.indexOf(';', position);
            if (end < 0) end = contents.length();
            int equals = separator(contents, position, end);
            if (equals >= position && equals < end) {
                String key = contents.substring(position, equals).strip();
                if (key.equalsIgnoreCase("Max-Age")) {
                    try {
                        maxAge = Long.parseLong(contents.substring(equals + 1, end).strip());
                    } catch (NumberFormatException ignored) { }
                } else if (key.equalsIgnoreCase("Expires")) {
                    expires = expires(contents.substring(equals + 1, end).strip());
                }
            }
            position = end + 1;
        }
        return new Field(name, value, true, maxAge, expires);
    }

    private static int separator(String header, int start, int end) {
        for (int index = start; index < end; index++) {
            if (header.charAt(index) == '=') return index;
        }
        return -1;
    }

    private static Long expires(String text) {
        for (var format : List.of(DateTimeFormatter.RFC_1123_DATE_TIME, DASHED_DATE)) {
            try {
                return ZonedDateTime.parse(text, format).toInstant().toEpochMilli();
            } catch (DateTimeParseException ignored) { }
        }
        return null;
    }
}
