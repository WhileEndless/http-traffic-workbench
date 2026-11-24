package trafficworkbench;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

final class Util {
    static final int MAX_BODY_BYTES = 4 * 1024 * 1024;

    record MessageText(String body, String contentType, String query, Charset charset) {
        List<FieldExtractor.Pair> fields() {
            return FieldExtractor.pairs(body, contentType, query, charset);
        }

        List<FieldExtractor.Pair> searchFields() {
            return FieldExtractor.searchPairs(body, contentType, query, charset);
        }

        String searchable() {
            return query == null || query.isEmpty() ? body : query + "\n" + body;
        }
    }

    private Util() {}

    static MessageText text(HttpMessage message, String query) {
        return text(message, query, MAX_BODY_BYTES);
    }

    static MessageText text(HttpMessage message, String query, int limit) {
        if (message == null) {
            return new MessageText("", null, query, StandardCharsets.UTF_8);
        }
        String contentType = message.headerValue("Content-Type");
        var body = message.body();
        boolean truncated = body.length() > limit;
        byte[] bytes = truncated ? body.subArray(0, limit).getBytes() : body.getBytes();
        Charset charset = charset(contentType, bytes);
        byte[] decoded = unpack(bytes, message.headerValue("Content-Encoding"), limit, truncated);
        if (decoded != bytes) {
            charset = charset(contentType, decoded);
        }
        return new MessageText(new String(decoded, 0, Math.min(decoded.length, limit), charset),
                contentType, query, charset);
    }

    private static byte[] unpack(byte[] bytes, String encoding, int limit, boolean truncated) {
        if (bytes.length >= 2 && (bytes[0] & 255) == 31 && (bytes[1] & 255) == 139) {
            try (var input = new GZIPInputStream(new ByteArrayInputStream(bytes))) {
                return input.readNBytes(limit);
            } catch (IOException ignored) {
                return truncated ? new byte[0] : bytes;
            }
        }
        if ("deflate".equalsIgnoreCase(encoding)) {
            try (var input = new InflaterInputStream(new ByteArrayInputStream(bytes))) {
                return input.readNBytes(limit);
            } catch (IOException ignored) {
                return truncated ? new byte[0] : bytes;
            }
        }
        return bytes;
    }

    private static Charset charset(String contentType, byte[] bytes) {
        String declared = parameter(contentType, "charset");
        if (declared != null) {
            try {
                return Charset.forName(declared);
            } catch (IllegalArgumentException ignored) {
                // Fall back to BOM detection and UTF-8.
            }
        }
        if (bytes.length > 1 && ((bytes[0] & 255) == 255 && (bytes[1] & 255) == 254
                || (bytes[0] & 255) == 254 && (bytes[1] & 255) == 255)) {
            return StandardCharsets.UTF_16;
        }
        return StandardCharsets.UTF_8;
    }

    static String parameter(String header, String name) {
        if (header == null) {
            return null;
        }
        var matcher = Pattern.compile("(?i)(?:^|;)\\s*" + Pattern.quote(name)
                + "\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]+))").matcher(header);
        if (!matcher.find()) {
            return null;
        }
        return matcher.group(1) == null ? matcher.group(2) : matcher.group(1);
    }

    static long contentHash(HttpRequestResponse exchange) {
        int request = Arrays.hashCode(exchange.request().toByteArray().getBytes());
        int response = exchange.response() == null ? 0 : Arrays.hashCode(exchange.response().toByteArray().getBytes());
        return ((long) request << 32) | Integer.toUnsignedLong(response);
    }

    static MessageText requestText(HttpRequestResponse exchange) {
        return text(exchange.request(), exchange.request().query());
    }

    static MessageText responseText(HttpRequestResponse exchange) {
        return text(exchange.response(), null);
    }
}
