package trafficworkbench;

import javax.swing.text.html.parser.DTD;
import javax.swing.text.html.parser.ParserDelegator;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SearchEncoding {
    private static final Pattern HTML_REFERENCE = Pattern.compile(
            "&(#(?:[0-9]{1,10}|[xX][0-9a-fA-F]{1,8})|[A-Za-z][A-Za-z0-9]{1,31});");
    private static final Pattern URL_BYTES = Pattern.compile("(?:%[0-9a-fA-F]{2})++");

    private SearchEncoding() {}

    static String url(String value, Charset charset) {
        if (value.indexOf('%') < 0) return value;
        // A plus is literal outside a form. Form fields are already decoded by the field extractor.
        return FieldExtractor.decodeFormComponent(value.replace("+", "%2B"), charset);
    }

    static String url(String value) {
        return url(value, StandardCharsets.UTF_8);
    }

    static String html(String value) {
        if (value.indexOf('&') < 0 || value.indexOf(';') < 0) return value;
        var references = HTML_REFERENCE.matcher(value);
        if (!references.find()) return value;
        var decoded = new StringBuilder(value.length());
        do {
            String replacement = reference(references.group(1));
            references.appendReplacement(decoded, Matcher.quoteReplacement(
                    replacement == null ? references.group() : replacement));
        } while (references.find());
        return references.appendTail(decoded).toString();
    }

    static boolean matchesDecoded(String value, boolean decodeUrl, Predicate<String> test) {
        String decoded = decodeUrl ? url(value) : value;
        if (!decoded.equals(value) && test.test(decoded)) return true;
        decoded = html(value);
        return !decoded.equals(value) && test.test(decoded);
    }

    static TimedRegex.Span originalUrlSpan(String original, TimedRegex.Span span, Charset charset) {
        return originalSpan(URL_BYTES.matcher(original), span, token -> url(token.group(), charset));
    }

    static TimedRegex.Span originalHtmlSpan(String original, TimedRegex.Span span) {
        return originalSpan(HTML_REFERENCE.matcher(original), span, token -> reference(token.group(1)));
    }

    private static TimedRegex.Span originalSpan(Matcher tokens, TimedRegex.Span span, Function<Matcher, String> decode) {
        int shift = 0;
        int start = -1;
        while (tokens.find()) {
            int decodedStart = tokens.start() + shift;
            if (start < 0 && span.start() < decodedStart) start = span.start() - shift;
            if (span.end() <= decodedStart) return new TimedRegex.Span(start, span.end() - shift, false);
            String replacement = decode.apply(tokens);
            if (replacement == null || replacement.equals(tokens.group())) continue;
            int decodedEnd = decodedStart + replacement.length();
            if (start < 0 && span.start() < decodedEnd) start = tokens.start();
            if (span.end() <= decodedEnd) return new TimedRegex.Span(start, tokens.end(), false);
            shift += replacement.length() - (tokens.end() - tokens.start());
        }
        return new TimedRegex.Span(start < 0 ? span.start() - shift : start, span.end() - shift, false);
    }

    private static String reference(String name) {
        if (name.startsWith("#")) {
            boolean hex = name.charAt(1) == 'x' || name.charAt(1) == 'X';
            long codePoint = Long.parseLong(name.substring(hex ? 2 : 1), hex ? 16 : 10);
            if (codePoint == 0 || codePoint > Character.MAX_CODE_POINT
                    || codePoint >= Character.MIN_SURROGATE && codePoint <= Character.MAX_SURROGATE) return null;
            return Character.toString((int) codePoint);
        }
        return switch (name) {
            case "AMP" -> "&";
            case "LT" -> "<";
            case "GT" -> ">";
            case "QUOT" -> "\"";
            case "apos" -> "'";
            case "sol" -> "/";
            case "dollar" -> "$";
            case "percnt" -> "%";
            case "plus" -> "+";
            default -> {
                var entity = HtmlEntities.TABLE.getEntity(name);
                yield entity == null ? null : entity.getString();
            }
        };
    }

    private static final class HtmlEntities {
        private static final DTD TABLE = load();

        private static DTD load() {
            new ParserDelegator();
            try {
                return DTD.getDTD("html32");
            } catch (IOException ex) {
                throw new IllegalStateException("Could not load HTML character references", ex);
            }
        }
    }
}
