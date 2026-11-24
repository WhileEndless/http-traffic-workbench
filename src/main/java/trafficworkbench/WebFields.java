package trafficworkbench;

import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;

final class WebFields {
    private static final Pattern HTML_TAG = Pattern.compile(
            "(?i)<(?:html|head|body|input|output|textarea|select|script|form|div|span|pre|code|main|section|article|p|meta|template)(?=[\\s>/])");
    private static final Pattern HTML_ROOT = Pattern.compile(
            "(?i)^<(?:!doctype\\s+html|html|head|body)(?=[\\s>/])");
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?<![=!<>])\\s*([:=])\\s*(?![=>])");
    private static final Pattern NUMBER = Pattern.compile("-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?");

    private WebFields() {}

    static boolean looksLikeHtml(String text) {
        return HTML_TAG.matcher(text).find();
    }

    static boolean hasHtmlRoot(String text) {
        return HTML_ROOT.matcher(text).find();
    }

    interface HtmlField {
        void accept(String key, String value, boolean domId, boolean domAlias);
    }

    static void html(String text, HtmlField field, Consumer<String> script,
                     Consumer<String> embedded) {
        // Parse locally as markup. ParserDelegator has no document loading or script engine.
        var controls = new ArrayDeque<Control>();
        try {
            new ParserDelegator().parse(new StringReader(text), new HTMLEditorKit.ParserCallback() {
                private boolean inScript;

                @Override
                public void handleStartTag(HTML.Tag tag, MutableAttributeSet attributes, int position) {
                    start(tag.toString(), attributes);
                }

                @Override
                public void handleSimpleTag(HTML.Tag tag, MutableAttributeSet attributes, int position) {
                    if (attributes.isDefined(HTML.Attribute.ENDTAG)) {
                        end(tag.toString());
                    } else {
                        start(tag.toString(), attributes);
                    }
                }

                @Override
                public void handleEndTag(HTML.Tag tag, int position) {
                    end(tag.toString());
                }

                @Override
                public void handleText(char[] data, int position) {
                    if (inScript) {
                        script.accept(new String(data));
                    } else {
                        if (!controls.isEmpty()) controls.peek().text.append(data);
                        embedded.accept(new String(data));
                    }
                }

                @Override
                public void handleComment(char[] data, int position) {
                    if (inScript) script.accept(new String(data));
                    else embedded.accept(new String(data));
                }

                private void start(String tag, MutableAttributeSet attributes) {
                    String name = attribute(attributes, HTML.Attribute.NAME);
                    String id = attribute(attributes, HTML.Attribute.ID);
                    String value = attribute(attributes, HTML.Attribute.VALUE);
                    if (tag.equals("script")) {
                        inScript = true;
                    }
                    if (tag.equals("input") || tag.equals("meta")) {
                        if (tag.equals("meta")) {
                            value = attribute(attributes, HTML.Attribute.CONTENT);
                        }
                        emit(field, name, id, value);
                    } else if (tag.equals("textarea") || tag.equals("output") || tag.equals("select")) {
                        emit(field, name, id, value);
                        if (controls.size() < 64) {
                            controls.push(new Control(tag, name, id, value));
                        }
                    } else if (tag.equals("option") && !controls.isEmpty() && controls.peek().tag.equals("select")) {
                        controls.push(new Control(tag, controls.peek().name, controls.peek().id, value));
                    } else if (!id.isEmpty() && !value.isEmpty()) {
                        emit(field, name, id, value);
                    }
                    var names = attributes.getAttributeNames();
                    while (names.hasMoreElements()) {
                        Object key = names.nextElement();
                        String attribute = key.toString().toLowerCase(Locale.ROOT);
                        String data = attribute(attributes, key);
                        if (attribute.startsWith("data-") && attribute.length() > 5) {
                            field.accept(attribute, data, false, false);
                            field.accept(attribute.substring(5), data, false, false);
                        }
                        if (attribute.startsWith("on") && attribute.length() > 2) script.accept(data);
                        else embedded.accept(data);
                    }
                }

                private void end(String tag) {
                    if (tag.equals("script")) {
                        inScript = false;
                    }
                    if (!controls.isEmpty() && controls.peek().tag.equals(tag)) {
                        Control control = controls.pop();
                        if (control.value.isEmpty() && !tag.equals("select")) {
                            emit(field, control.name, control.id, control.text.toString().strip());
                        } else if (tag.equals("option")) {
                            emit(field, control.name, control.id, control.value);
                        }
                    }
                }
            }, true);
        } catch (IOException ignored) {
            // The original source is still searchable.
        }
    }

    private static String attribute(MutableAttributeSet attributes, Object key) {
        Object value = attributes.getAttribute(key);
        return value == null ? "" : value.toString();
    }

    private static void emit(HtmlField field, String name, String id, String value) {
        if (!name.isEmpty()) {
            field.accept(name, value, false, false);
        }
        if (!id.isEmpty() && !id.equals(name)) {
            field.accept(id, value, true, !name.isEmpty());
        }
    }

    static void script(String text, BiConsumer<String, String> field, Consumer<String> embedded,
                       java.util.function.IntUnaryOperator structuredBlock) {
        var assignment = ASSIGNMENT.matcher(text);
        int index = 0;
        while (index < text.length() && !Thread.currentThread().isInterrupted()) {
            char first = text.charAt(index);
            if (first == '{' || first == '[') {
                int end = structuredBlock.applyAsInt(index);
                if (end > index) {
                    index = end;
                    continue;
                }
            }
            Token token = token(text, index);
            index = Math.max(index + 1, token.end);
            embeddedLiteral(token, embedded);
            if (token.value.isEmpty() || !token.named || index >= text.length()) {
                continue;
            }
            assignment.region(index, text.length());
            if (!assignment.lookingAt()) {
                continue;
            }
            Token value = token(text, assignment.end());
            if (value.literal) {
                int after = value.end;
                while (after < text.length() && (text.charAt(after) == ' ' || text.charAt(after) == '\t')) {
                    after++;
                }
                if (after == text.length() || ",;}]\r\n".indexOf(text.charAt(after)) >= 0) {
                    field.accept(token.value, value.value);
                    embeddedLiteral(value, embedded);
                    index = value.end;
                }
            }
        }
    }

    private static void embeddedLiteral(Token token, Consumer<String> embedded) {
        if (token.literal && token.named) {
            String value = token.value.stripLeading();
            if (value.startsWith("{") || value.startsWith("[")) embedded.accept(value);
        }
    }

    private static Token token(String text, int start) {
        if (start >= text.length()) {
            return new Token("", start, false, false);
        }
        char first = text.charAt(start);
        if (first == '/' && start + 1 < text.length()) {
            char next = text.charAt(start + 1);
            if (next == '/' || next == '*') {
                int end = text.indexOf(next == '/' ? "\n" : "*/", start + 2);
                return new Token("", end < 0 ? text.length() : end + (next == '/' ? 1 : 2), false, false);
            }
        }
        if (first == '\'' || first == '"' || first == '`') {
            StringBuilder value = new StringBuilder();
            boolean interpolation = false;
            int end = start + 1;
            while (end < text.length()) {
                char current = text.charAt(end++);
                if (current == first) {
                    return new Token(value.toString(), end, !interpolation, !interpolation);
                }
                if (current == '\\' && end < text.length()) {
                    char escaped = text.charAt(end++);
                    if ((escaped == 'u' || escaped == 'x') && end + (escaped == 'u' ? 4 : 2) <= text.length()) {
                        int width = escaped == 'u' ? 4 : 2;
                        try {
                            value.append((char) Integer.parseInt(text.substring(end, end + width), 16));
                            end += width;
                            continue;
                        } catch (NumberFormatException ignored) {
                            // Keep the escaped character in malformed source.
                        }
                    }
                    value.append(switch (escaped) {
                        case 'n' -> '\n';
                        case 'r' -> '\r';
                        case 't' -> '\t';
                        default -> escaped;
                    });
                    continue;
                }
                interpolation |= first == '`' && current == '$' && end < text.length() && text.charAt(end) == '{';
                value.append(current);
            }
            return new Token("", end, false, false);
        }
        int end = start;
        if (Character.isJavaIdentifierStart(first)) {
            do {
                end++;
            } while (end < text.length() && Character.isJavaIdentifierPart(text.charAt(end)));
            String value = text.substring(start, end);
            return new Token(value, end, true, value.equals("true") || value.equals("false"));
        }
        if (Character.isDigit(first) || first == '-') {
            var number = NUMBER.matcher(text).region(start, text.length());
            if (number.lookingAt()) {
                return new Token(number.group(), number.end(), false, true);
            }
        }
        return new Token("", start + 1, false, false);
    }

    private record Token(String value, int end, boolean named, boolean literal) {}

    private static final class Control {
        private final String tag;
        private final String name;
        private final String id;
        private final String value;
        private final StringBuilder text = new StringBuilder();

        private Control(String tag, String name, String id, String value) {
            this.tag = tag;
            this.name = name;
            this.id = id;
            this.value = value;
        }
    }
}
