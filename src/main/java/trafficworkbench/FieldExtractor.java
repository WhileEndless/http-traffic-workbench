package trafficworkbench;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

final class FieldExtractor {
    private static final int MAX_DEPTH = 64;
    private static final int MAX_FIELDS = 25_000;
    private static final int MAX_EMBEDDED_CHARS = 1024 * 1024;
    private static final int MAX_TEXT_FIELDS_CHARS = 256 * 1024;
    private static final Pattern FORM_KEY = Pattern.compile("[^=&\\r\\n\\p{Cntrl} ]+");
    private static final Pattern EMBEDDED_FORM_KEY = Pattern.compile("[\\p{L}\\p{N}_.$%+\\[\\]-]+");
    private static final Pattern FORM_ESCAPE = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern TEXT_FIELD = Pattern.compile("([\\p{L}_$][\\p{L}\\p{N}.$_\\[\\]-]*):[ \\t]*(.*)");
    private static final Pattern INVALID_ESCAPE = Pattern.compile("%(?![0-9a-fA-F]{2})");
    private static final Pattern PART_NAME = Pattern.compile(
            "(?im)^Content-Disposition:[^\\r\\n]*?;\\s*name\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]+))");
    private static final Pattern PART_TYPE = Pattern.compile("(?im)^Content-Type:[ \\t]*([^\\r\\n]+)");

    private FieldExtractor() {}

    enum Kind { BODY, HEADER, COOKIE }

    record FormToken(Charset charset, String name, String value) {}

    static final class Pair {
        final String key;
        final String value;
        final int objId;
        final Kind kind;
        final FormToken form;
        final boolean domId;
        final boolean domAlias;

        Pair(String key, String value, int objId) {
            this(key, value, objId, Kind.BODY);
        }

        Pair(String key, String value, int objId, Kind kind) {
            this(key, value, objId, kind, null);
        }

        Pair(String key, String value, int objId, Kind kind, FormToken form) {
            this(key, value, objId, kind, form, false, false);
        }

        Pair(String key, String value, int objId, Kind kind, FormToken form, boolean domId, boolean domAlias) {
            this.key = key;
            this.value = value;
            this.objId = objId;
            this.kind = kind;
            this.form = form;
            this.domId = domId;
            this.domAlias = domAlias;
        }

        String wireKey() { return form == null ? key : form.name(); }
        String wireValue() { return form == null ? value : form.value(); }
    }

    static List<Pair> pairs(String body) {
        return pairs(body, null, null, StandardCharsets.UTF_8);
    }

    static List<Pair> pairs(String body, String contentType, String query, Charset charset) {
        return pairs(body, contentType, query, charset, false);
    }

    static List<Pair> searchPairs(String body, String contentType, String query, Charset charset) {
        return pairs(body, contentType, query, charset, true);
    }

    private static List<Pair> pairs(String body, String contentType, String query, Charset charset, boolean tolerant) {
        Fields fields = new Fields(tolerant);
        if (query != null && !query.isEmpty()) {
            fields.form(query, charset, true);
        }
        if (body == null || body.isBlank()) {
            return fields.result;
        }
        String text = body.strip();
        if (text.startsWith("\uFEFF")) {
            text = text.substring(1).stripLeading();
        }
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        boolean structuredJson = startsJson(text);
        if (structuredJson && fields.json(text, 0)) {
            return fields.result;
        }
        if (type.startsWith("multipart/") && fields.multipart(text, contentType, 0)) {
            return fields.result;
        }
        if (looksLikeHtml(text, type)) {
            fields.html(text);
        } else if (text.startsWith("<")) {
            fields.xml(text);
        } else if (type.stripLeading().startsWith("application/x-www-form-urlencoded")) {
            fields.form(text, charset, true);
        } else if (singleLine(text) && text.indexOf('%') >= 0 && text.indexOf('%') < text.indexOf('=')
                && looksLikeForm(text)) {
            fields.form(text, charset, false);
        } else if (type.contains("javascript") || type.contains("ecmascript")) {
            fields.script(text);
        } else if (structuredJson && tolerant) {
            if (!fields.json(text, 0, Strictness.LENIENT)) fields.staticScript(text);
        } else if (!structuredJson && singleLine(text) && looksLikeForm(text)) {
            fields.form(text, charset, false);
        } else if (!structuredJson && tolerant && text.length() <= MAX_TEXT_FIELDS_CHARS) {
            if (text.indexOf('{') >= 0 && text.indexOf('}') >= 0) fields.script(text);
            if (text.indexOf('=') >= 0 || text.indexOf(':') >= 0) fields.textFields(text, charset);
        }
        return fields.result;
    }

    private static boolean looksLikeHtml(String text, String contentType) {
        return text.startsWith("<") && (WebFields.hasHtmlRoot(text)
                || !contentType.contains("xml") && (contentType.contains("html") || WebFields.looksLikeHtml(text)));
    }

    private static boolean singleLine(String text) {
        return text.indexOf('\r') < 0 && text.indexOf('\n') < 0;
    }

    private static boolean startsJson(String text) {
        return !text.isEmpty() && (text.charAt(0) == '{' || text.charAt(0) == '[');
    }

    private static boolean looksLikeForm(String text) {
        int equals = text.indexOf('=');
        return equals > 0 && FORM_KEY.matcher(text.substring(0, equals)).matches();
    }

    static String decodeFormComponent(String text) {
        return decodeFormComponent(text, StandardCharsets.UTF_8);
    }

    static String decodeFormComponent(String text, Charset charset) {
        if (text.indexOf('%') < 0 && text.indexOf('+') < 0) return text;
        try {
            return URLDecoder.decode(text, charset);
        } catch (IllegalArgumentException ignored) {
            return URLDecoder.decode(INVALID_ESCAPE.matcher(text).replaceAll("%25"), charset);
        }
    }

    static Set<String> keysForValue(List<Pair> pairs, String value) {
        Set<String> keys = new LinkedHashSet<>();
        if (value != null && !value.isEmpty()) {
            for (Pair pair : pairs) {
                if (pair.value.equals(value)) {
                    keys.add(pair.key);
                }
            }
        }
        return keys;
    }

    static boolean isKey(List<Pair> pairs, String name) {
        return pairs.stream().anyMatch(pair -> pair.kind == Kind.HEADER
                ? pair.key.equalsIgnoreCase(name) : pair.key.equals(name));
    }

    static String identifier(List<Pair> pairs, String field) {
        String value = "";
        for (var pair : pairs) {
            if (!field.equals(pair.key)) continue;
            String candidate = pair.value.strip();
            if (candidate.isEmpty() || candidate.length() > 256
                    || candidate.chars().anyMatch(Character::isISOControl)) continue;
            if (!value.isEmpty() && !value.equals(candidate)) return "";
            value = candidate;
        }
        return value;
    }

    private static final class Fields {
        private final List<Pair> result = new ArrayList<>();
        private final boolean tolerant;
        private int group;
        private int embeddedBudget = MAX_EMBEDDED_CHARS;

        private Fields(boolean tolerant) {
            this.tolerant = tolerant;
        }

        private void add(String key, String value, int id) {
            add(key, value, id, null);
        }

        private void add(String key, String value, int id, FormToken form) {
            add(new Pair(key, value, id, Kind.BODY, form));
        }

        private void add(Pair pair) {
            if (pair.key != null && !pair.key.isEmpty() && result.size() < MAX_FIELDS) result.add(pair);
        }

        private boolean json(String text, int nested) {
            return json(text, nested, Strictness.STRICT);
        }

        private boolean json(String text, int nested, Strictness strictness) {
            if (result.size() >= MAX_FIELDS) return true;
            int initialSize = result.size();
            try (JsonReader reader = new JsonReader(new StringReader(text))) {
                reader.setStrictness(strictness);
                visitJson(reader, null, -1, 0, nested);
                if (reader.peek() == JsonToken.END_DOCUMENT) return true;
            } catch (IllegalStateException | IOException ignored) {
                // Keep malformed input available through plain-text search.
            }
            result.subList(initialSize, result.size()).clear();
            return false;
        }

        private void visitJson(JsonReader reader, String key, int id, int depth, int nested) throws IOException {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException();
            if (depth > MAX_DEPTH || result.size() >= MAX_FIELDS) {
                reader.skipValue();
                return;
            }
            switch (reader.peek()) {
                case BEGIN_OBJECT -> {
                    int object = ++group;
                    reader.beginObject();
                    while (reader.hasNext()) {
                        String name = reader.nextName();
                        visitJson(reader, name, object, depth + 1, nested);
                    }
                    reader.endObject();
                }
                case BEGIN_ARRAY -> {
                    reader.beginArray();
                    while (reader.hasNext()) {
                        visitJson(reader, key, id, depth + 1, nested);
                    }
                    reader.endArray();
                }
                case NULL -> reader.nextNull();
                case BOOLEAN -> add(key, Boolean.toString(reader.nextBoolean()), id);
                case STRING, NUMBER -> {
                    String value = reader.nextString();
                    add(key, value, id);
                    if (nested < 2) nestedValue(value, nested + 1);
                }
                default -> throw new IOException("Unexpected JSON token");
            }
        }

        private void nestedValue(String value, int depth) {
            String nested = value.strip();
            if (nested.startsWith("{") || nested.startsWith("[")) {
                json(nested, depth);
            } else if (tolerant && nested.length() <= embeddedBudget && looksLikeEmbeddedForm(nested)) {
                embeddedBudget -= nested.length();
                form(nested, StandardCharsets.UTF_8, false, false);
            }
        }

        private static boolean looksLikeEmbeddedForm(String value) {
            int equals = value.indexOf('=');
            if (equals < 1 || !EMBEDDED_FORM_KEY.matcher(value.substring(0, equals)).matches() || !singleLine(value)) {
                return false;
            }
            if (FORM_ESCAPE.matcher(value).find()) return true;
            int amp = value.indexOf('&', equals + 1);
            int nextEquals = amp < 0 ? -1 : value.indexOf('=', amp + 1);
            return nextEquals > amp + 1 && EMBEDDED_FORM_KEY.matcher(value.substring(amp + 1, nextEquals)).matches();
        }

        private void form(String body, Charset charset, boolean allowBareNames) {
            form(body, charset, allowBareNames, true);
        }

        private void form(String body, Charset charset, boolean allowBareNames, boolean unpackValues) {
            int id = ++group;
            int start = 0;
            while (start < body.length() && result.size() < MAX_FIELDS && !Thread.currentThread().isInterrupted()) {
                int end = body.indexOf('&', start);
                if (end == -1) {
                    end = body.length();
                }
                int equals = start;
                while (equals < end && body.charAt(equals) != '=') equals++;
                if (equals > start && (equals < end || allowBareNames)) {
                    String rawKey = body.substring(start, equals).strip();
                    String rawValue = equals < end ? body.substring(equals + 1, end) : "";
                    String value = decodeFormComponent(rawValue, charset);
                    add(decodeFormComponent(rawKey, charset), value, id, new FormToken(charset, rawKey, rawValue));
                    if (unpackValues) embeddedBody(value, "", 1);
                }
                start = end + 1;
            }
        }

        private void textFields(String text, Charset charset) {
            var lines = text.lines().iterator();
            int id = ++group;
            while (lines.hasNext() && result.size() < MAX_FIELDS && !Thread.currentThread().isInterrupted()) {
                String line = lines.next().strip();
                if (looksLikeForm(line)) {
                    form(line, charset, false);
                } else {
                    var field = TEXT_FIELD.matcher(line);
                    if (field.matches()) add(field.group(1), field.group(2), id);
                }
            }
        }

        private void embeddedBody(String value, String contentType, int depth) {
            String text = value.strip();
            String type = contentType.toLowerCase(Locale.ROOT);
            if (startsJson(text)) {
                json(text, depth);
            } else if (type.startsWith("multipart/") && depth < 4) {
                multipart(text, contentType, depth);
            } else if (looksLikeHtml(text, type)) {
                html(text);
            } else if (text.startsWith("<")) {
                xml(text);
            } else if (type.contains("javascript") || type.contains("ecmascript")) {
                script(text);
            }
        }

        private boolean xml(String body) {
            var factory = XMLInputFactory.newDefaultFactory();
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setXMLResolver((publicId, systemId, base, namespace) -> {
                throw new XMLStreamException("External XML entities are disabled");
            });
            var stack = new ArrayDeque<XmlField>();
            int initialSize = result.size();
            try {
                var reader = factory.createXMLStreamReader(new StringReader(body));
                try {
                    while (reader.hasNext() && result.size() < MAX_FIELDS && !Thread.currentThread().isInterrupted()) {
                        switch (reader.next()) {
                            case XMLStreamConstants.DTD -> throw new XMLStreamException("DTD is disabled");
                            case XMLStreamConstants.START_ELEMENT -> {
                                if (stack.size() >= MAX_DEPTH) {
                                    throw new XMLStreamException("XML nesting limit");
                                }
                                if (!stack.isEmpty()) {
                                    stack.peek().hasChildren = true;
                                }
                                XmlField field = new XmlField(reader.getLocalName(), ++group);
                                stack.push(field);
                                for (int i = 0; i < reader.getAttributeCount(); i++) {
                                    add(reader.getAttributeLocalName(i), reader.getAttributeValue(i), field.id);
                                }
                            }
                            case XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA -> {
                                if (!stack.isEmpty() && !stack.peek().hasChildren) {
                                    stack.peek().text.append(reader.getText());
                                }
                            }
                            case XMLStreamConstants.END_ELEMENT -> {
                                XmlField field = stack.pop();
                                if (!field.hasChildren) {
                                    int id = stack.isEmpty() ? field.id : stack.peek().id;
                                    String value = field.text.toString().strip();
                                    add(field.key, value, id);
                                    nestedValue(value, 1);
                                }
                            }
                            default -> { }
                        }
                    }
                } finally {
                    reader.close();
                }
            } catch (XMLStreamException ignored) {
                result.subList(initialSize, result.size()).clear();
                return false;
            }
            return true;
        }

        private void script(String body) {
            String text = body.strip();
            if (startsJson(text) && json(text, 0)) return;
            staticScript(text);
        }

        private void staticScript(String body) {
            int id = ++group;
            WebFields.script(body, (key, value) -> add(key, value, id), this::embeddedJson,
                    index -> embeddedAt(body, index));
        }

        private void html(String body) {
            int id = ++group;
            WebFields.html(body, (key, value, domId, domAlias) ->
                    add(new Pair(key, value, id, Kind.BODY, null, domId, domAlias)),
                    this::script, this::embeddedJson);
        }

        private int embeddedAt(String text, int start) {
            if (embeddedBudget <= 0 || result.size() >= MAX_FIELDS) return start;
            int limit = Math.min(text.length(), start + embeddedBudget);
            int value = start + 1;
            while (value < limit && Character.isWhitespace(text.charAt(value))) value++;
            if (value == limit || !jsonValueStart(text.charAt(start), text.charAt(value))) return start;
            int end = blockEnd(text, value, limit);
            embeddedBudget -= (end < 0 ? limit : end) - start;
            return end > value && json(text.substring(start, end), 0) ? end : start;
        }

        private void embeddedJson(String text) {
            if (embeddedBudget <= 0 || result.size() >= MAX_FIELDS) return;
            int limit = Math.min(text.length(), embeddedBudget);
            embeddedBudget -= limit;
            int index = 0;
            while (index < limit && result.size() < MAX_FIELDS && !Thread.currentThread().isInterrupted()) {
                int start = index++;
                char open = text.charAt(start);
                if (open != '{' && open != '[') continue;
                while (index < limit && Character.isWhitespace(text.charAt(index))) index++;
                if (index == limit || !jsonValueStart(open, text.charAt(index))) continue;
                int end = blockEnd(text, index, limit);
                if (end <= index) break;
                json(text.substring(start, end), 0);
                index = end;
            }
        }

        private static boolean jsonValueStart(char open, char value) {
            return open == '{' ? value == '"' || value == '}'
                    : value == '"' || value == '{' || value == '[' || value == ']'
                    || value == '-' || Character.isDigit(value) || value == 't' || value == 'f' || value == 'n';
        }

        private static int blockEnd(String text, int index, int limit) {
            int depth = 1;
            char quote = 0;
            boolean escape = false;
            for (; index < limit; index++) {
                char ch = text.charAt(index);
                if (quote != 0) {
                    if (escape) escape = false;
                    else if (ch == '\\') escape = true;
                    else if (ch == quote) quote = 0;
                } else if (ch == '"' || ch == '\'' || ch == '`') {
                    quote = ch;
                } else if (ch == '{' || ch == '[') {
                    depth++;
                } else if ((ch == '}' || ch == ']') && --depth == 0) {
                    return index + 1;
                }
            }
            return -1;
        }

        private boolean multipart(String body, String contentType, int depth) {
            String boundary = Util.parameter(contentType, "boundary");
            if (boundary == null || boundary.isBlank() || boundary.length() > 200) {
                return false;
            }
            var boundaries = Pattern.compile("(?m)^--" + Pattern.quote(boundary) + "(--)?[ \\t]*\\r?$")
                    .matcher(body);
            int previous = -1;
            int id = ++group;
            while (result.size() < MAX_FIELDS && !Thread.currentThread().isInterrupted() && boundaries.find()) {
                if (previous >= 0) {
                    String part = body.substring(previous, boundaries.start()).replaceFirst("^\\n", "");
                    int split = part.indexOf("\r\n\r\n");
                    int separator = 4;
                    if (split < 0) {
                        split = part.indexOf("\n\n");
                        separator = 2;
                    }
                    if (split >= 0) {
                        String headers = part.substring(0, split);
                        String value = part.substring(split + separator).replaceFirst("\\r?\\n$", "");
                        var type = PART_TYPE.matcher(headers);
                        String partType = type.find() ? type.group(1).strip() : "";
                        var name = PART_NAME.matcher(headers);
                        if (name.find()) {
                            String key = name.group(1) == null ? name.group(2) : name.group(1);
                            if (!headers.toLowerCase(Locale.ROOT).contains("filename=")
                                    && !partType.toLowerCase(Locale.ROOT).startsWith("multipart/")) {
                                add(key, value, id);
                            }
                        }
                        embeddedBody(value, partType, depth + 1);
                    }
                }
                if (boundaries.group(1) != null) {
                    return true;
                }
                previous = boundaries.end();
            }
            return previous >= 0;
        }

    }

    private static final class XmlField {
        private final String key;
        private final int id;
        private final StringBuilder text = new StringBuilder();
        private boolean hasChildren;

        private XmlField(String key, int id) {
            this.key = key;
            this.id = id;
        }
    }
}
