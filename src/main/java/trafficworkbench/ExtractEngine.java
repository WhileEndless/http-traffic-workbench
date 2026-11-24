package trafficworkbench;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import trafficworkbench.FieldExtractor.Kind;
import java.util.Set;

/** Searches both message sides and expands relationships through exact shared field values. */
final class ExtractEngine {

    interface Sink {
        void row(ResultRow row);
        void progress(String phase, int done, int total);
        boolean cancelled();
    }

    // Scores for matches on the selected endpoint and on other endpoints, respectively.
    private static final int[] KEY_AND_VALUE = {100, 85};
    private static final int[] KEY = {95, 80};
    private static final int[] VALUE = {70, 65};
    private static final int[] VALUE_PART = {55, 50};
    private static final int[] VALUE_FREE = {50, 45};
    private static final int[] CONTEXT_VARIANT = {44, 42};
    private static final int[] ALIAS_VARIANT = {41, 38};
    private static final int[] DERIVED = {36, 33};
    private static final int[] SIBLING = {30, 25};

    static final int MAX_ROWS = 50_000;
    private static final int MAX_FRONTIER = 500;
    private static final int MAX_VALUES_PER_LEVEL = 5_000;
    private static final int MAX_FANOUT = 4;
    private static final int MAX_KEY_VALUES = 150;
    private static final int MAX_VARIANT_VALUES = 25;
    private static final int MAX_VALUE_CHARS = 1_000;

    private static final String REQ = "Request";
    private static final String RESP = "Response";

    private final Iterable<CapturedEntry> entries;
    private final int totalEntries;
    private final String sourceEndpoint;
    private final int depth;
    private final boolean siblings;
    private final Sink sink;

    private final Map<MatchKey, ResultRow> emitted = new HashMap<>();
    private boolean truncated;
    private static final int MAX_DISCOVERY_PAIRS = 120_000;
    private static final int MAX_DISCOVERY_CHARACTERS = 12_000_000;
    private static final int MAX_KNOWN_LINK_HITS = 8_000;
    private static final int MAX_KNOWN_LINK_CHARACTERS = 1_000_000;
    private static final int MAX_VARIANT_HITS = 30_000;
    private static final int MAX_VARIANT_CHARACTERS = 2_000_000;
    private int indexedCharacters;
    private int indexedPairs;
    private int knownLinkHits;
    private int knownLinkCharacters;
    private boolean indexLimited;
    private final List<Hit> variantHits = new ArrayList<>();
    private int variantCharacters;
    private boolean variantLimitReached;
    private boolean discoveryLimited;
    private boolean regexLimited;

    boolean discoveryLimited() { return discoveryLimited || regexLimited; }
    private final Direction direction;
    private final boolean partial;
    private final boolean collapseRepeated;
    private final Map<IndexedField, Hit> indexed = new HashMap<>();
    enum Direction {
        BOTH("Request and response"), REQUEST("Request only"), RESPONSE("Response only");
        private final String label;
        Direction(String label) { this.label = label; }
        public String toString() { return label; }
    }
    private record MatchKey(Object location, String side, FieldId field, int valueLength, int valueHash, String preview) {}
    private record FieldId(Kind kind, String name) {}
    private record IndexedField(CapturedEntry.Key endpoint, String side, FieldId field, String value) {}

    private final Map<FieldId, List<Hit>> byKey = new HashMap<>();
    private final Map<String, List<Hit>> byValue = new HashMap<>();
    private final Set<FieldId> matchedFields = new LinkedHashSet<>();

    private static final class Hit {
        CapturedEntry entry;
        final String src;
        final FieldExtractor.Pair pair;
        final String linkValue;

        Hit(CapturedEntry entry, String src, FieldExtractor.Pair pair) {
            this(entry, src, pair, pair.value);
        }

        Hit(CapturedEntry entry, String src, FieldExtractor.Pair pair, String linkValue) {
            this.entry = entry;
            this.src = src;
            this.pair = pair;
            this.linkValue = linkValue;
        }
    }

    ExtractEngine(Collection<CapturedEntry> entries, String sourceEndpoint, int depth, boolean siblings,
                  Direction direction, boolean partial, boolean collapseRepeated, Sink sink) {
        this(entries, entries.size(), sourceEndpoint, depth, siblings, direction, partial, collapseRepeated, sink);
    }

    ExtractEngine(Iterable<CapturedEntry> entries, int totalEntries, String sourceEndpoint, int depth, boolean siblings,
                  Direction direction, boolean partial, boolean collapseRepeated, Sink sink) {
        this.totalEntries = totalEntries;
        this.siblings = siblings;
        this.entries = entries;
        this.sourceEndpoint = sourceEndpoint == null ? "" : sourceEndpoint;
        this.depth = Math.max(0, depth);
        this.direction = direction;
        this.partial = partial;
        this.collapseRepeated = collapseRepeated;
        this.sink = sink;
    }

    void runText(String value, boolean caseSensitive) {
        runText(literalPattern(value, caseSensitive), false, false);
    }

    void runText(Pattern needle, boolean timed, boolean negative) {
        int index = 0;
        for (var records = entries.iterator(); !stop() && records.hasNext();) {
            if ((index & 31) == 0) {
                if (index > 0) java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
                sink.progress("Searching text", index, totalEntries);
            }
            index++;
            var entry = records.next();
            if (entry == null) continue;
            var exchange = entry.requestResponse();
            boolean request = direction != Direction.RESPONSE;
            boolean response = direction != Direction.REQUEST && exchange.response() != null;
            var req = request ? findText(entry, REQ, Util.requestText(exchange), needle, timed, false) : null;
            var res = response ? findText(entry, RESP, Util.responseText(exchange), needle, timed, false) : null;
            boolean limited = incomplete(req) || incomplete(res);
            regexLimited |= limited;
            if (!negative) {
                emitText(entry, REQ, req);
                emitText(entry, RESP, res);
            } else if ((request || response) && !limited && req == null && res == null) {
                emit(entry, "—", "", "", VALUE_FREE, "No text match");
            }
        }
    }

    void runCookie(CookieTrace trace, java.util.function.Predicate<CapturedEntry> visible) {
        String active = trace.value();
        int index = 0;
        for (var records = entries.iterator(); !stop() && records.hasNext();) {
            if ((index & 31) == 0) {
                if (index > 0) java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
                sink.progress("Tracing cookie headers", index, totalEntries);
            }
            index++;
            var entry = records.next();
            if (entry == null || !trace.appliesTo(entry.requestResponse().request().httpService())) continue;
            var exchange = entry.requestResponse();
            if (!trace.followReplacements()) {
                showCookie(entry, trace.name(), direction != Direction.RESPONSE && trace.matches(exchange.request(), false),
                        direction != Direction.REQUEST && trace.matches(exchange.response(), true), "");
                continue;
            }

            var incoming = Cookies.fields(exchange.request(), false, trace.name());
            var outgoing = Cookies.fields(exchange.response(), true, trace.name());
            var distinctUpdates = outgoing.stream().distinct().limit(2).toList();
            String tracked = active;
            boolean requestMatch = incoming.stream().anyMatch(field -> field.value().equals(tracked));
            boolean responseMatch = outgoing.stream().anyMatch(field -> field.value().equals(tracked));
            Cookies.Field update = requestMatch && incoming.stream().map(Cookies.Field::value).distinct().count() == 1
                    && distinctUpdates.size() == 1 ? distinctUpdates.get(0) : null;
            boolean removed = update != null && update.expiredAt(entry.time());
            boolean rotated = update != null && !removed && !update.value().equals(active);
            if ((requestMatch || responseMatch) && visible.test(entry)) {
                showCookie(entry, trace.name(), direction != Direction.RESPONSE && requestMatch,
                        direction != Direction.REQUEST && (responseMatch || rotated || removed),
                        removed ? " · removed" : rotated ? " · replacement observed" : "");
            }
            if (removed) break;
            if (rotated) active = update.value();
        }
    }

    private void showCookie(CapturedEntry entry, String name, boolean request, boolean response, String update) {
        if (request) emit(entry, REQ, name, "Hidden", KEY_AND_VALUE, "Request Cookie", false, name);
        if (response) emit(entry, RESP, name, "Hidden", KEY_AND_VALUE, "Response Set-Cookie" + update, false, name);
    }

    void browse() {
        int index = 0;
        for (var records = entries.iterator(); !stop() && records.hasNext();) {
            if ((index & 31) == 0) sink.progress("Browsing records", index, totalEntries);
            index++;
            var entry = records.next();
            if (entry != null) emit(entry, "—", "", "", VALUE_FREE, "HTTP record");
        }
    }

    private static boolean incomplete(TextMatch text) {
        return text != null && text.span().limited();
    }

    private static Pattern literalPattern(String value, boolean caseSensitive) {
        return Pattern.compile(value, Pattern.LITERAL
                | (caseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE));
    }

    private void textMatch(CapturedEntry entry, String side, Util.MessageText text, Pattern needle) {
        var match = findText(entry, side, text, needle, false, true);
        if (match == null) {
            String body = text.body();
            String urlDecoded = SearchEncoding.url(body, text.charset());
            if (!urlDecoded.equals(body)) {
                var decoded = matchText(urlDecoded, needle, false);
                if (decoded != null) match = new TextMatch(body, SearchEncoding.originalUrlSpan(body, decoded.span(), text.charset()));
            }
            if (match == null) {
                String htmlDecoded = SearchEncoding.html(body);
                if (!htmlDecoded.equals(body)) {
                    var decoded = matchText(htmlDecoded, needle, false);
                    if (decoded != null) match = new TextMatch(body, SearchEncoding.originalHtmlSpan(body, decoded.span()));
                }
            }
        }
        emitText(entry, side, match);
    }

    private TextMatch findText(CapturedEntry entry, String side, Util.MessageText text, Pattern needle, boolean timed,
                               boolean maskHeaders) {
        var body = matchText(text.body(), needle, timed);
        if (body != null) return body;
        var exchange = entry.requestResponse();
        var message = side.equals(REQ) ? exchange.request() : exchange.response();
        String prefix = side.equals(REQ) ? exchange.request().method() + " " + exchange.request().path()
                : Short.toString(exchange.response().statusCode());
        String headers = message.headers().stream()
                .filter(header -> !maskHeaders || !HttpSearchFields.protectedHeader(header.name()))
                .map(h -> h.name() + ": " + h.value())
                .collect(java.util.stream.Collectors.joining("\n"));
        return matchText(prefix + "\n" + headers, needle, timed);
    }

    private static TextMatch matchText(String input, Pattern needle, boolean timed) {
        var span = TimedRegex.locate(needle, input, timed);
        if (!span.found() && !span.limited()) return null;
        return new TextMatch(input, span);
    }

    private void emitText(CapturedEntry entry, String side, TextMatch match) {
        if (match == null || !match.span().found()) return;
        int start = match.span().start();
        int end = match.span().end();
        int from = Math.max(0, start - 42);
        int until = Math.min(match.input().length(), end + 42);
        emit(entry, side, "", match.input().substring(from, until), VALUE_FREE, "Text match", false,
                end - start <= 512 ? match.input().substring(start, end) : "");
    }

    private record TextMatch(String input, TimedRegex.Span span) {}

    public boolean truncated() {
        return truncated;
    }


    public void runKey(List<String> keys) {
        runKeyFromContext(keys, List.of());
    }

    void runKeyFromContext(List<String> keys, List<FieldExtractor.Pair> context) {
        var names = new LinkedHashSet<String>();
        keys.forEach(key -> names.addAll(SearchTerm.of(key, context).spellings()));
        run(names, null, null, pairedValues(context, field ->
                names.contains(field.wireKey()) || matchesName(names, fieldId(field)), null));
    }

    public void runValue(String value, Set<String> primaryKeys) {
        run(primaryKeys == null ? new LinkedHashSet<>() : new LinkedHashSet<>(primaryKeys),
                value == null || value.isEmpty() ? null : SearchTerm.of(value), null, Map.of());
    }

    void runValueFromContext(String value, List<FieldExtractor.Pair> context) {
        var term = SearchTerm.of(value, context);
        run(depth > 0 ? term.keysIn(context) : Set.of(), term, null, Map.of());
    }

    void runAuto(String term, Set<String> contextFields, boolean caseSensitive) {
        runAuto(SearchTerm.of(term), contextFields, caseSensitive, Map.of());
    }

    void runAutoFromContext(String query, List<FieldExtractor.Pair> context, boolean caseSensitive) {
        var term = SearchTerm.of(query, context);
        var values = pairedValues(context, field -> term.names(field, fieldId(field)), term);
        runAuto(term, term.keysIn(context), caseSensitive, values);
    }

    private Map<String, String> pairedValues(List<FieldExtractor.Pair> context,
                                            Predicate<FieldExtractor.Pair> named, SearchTerm term) {
        var values = new LinkedHashMap<String, String>();
        if (depth > 0) {
            for (var field : context) {
                if (stop() || values.size() >= MAX_VARIANT_VALUES) break;
                if (named.test(field) && canFollowNamedField(field)) {
                    String linked = linkValue(field);
                    if (DiscoveryValues.linkableValue(linked)) values.putIfAbsent(linked, field.key);
                }
                if (term != null && HttpSearchFields.indexForDiscovery(field, HttpSearchFields.protectedValue(field))
                        && term.matches(field)) {
                    String name = linkSpelling(field, field.key);
                    if (DiscoveryValues.linkableValue(name)) values.putIfAbsent(name, name);
                }
            }
        }
        return values;
    }

    private void runAuto(SearchTerm term, Set<String> contextFields, boolean caseSensitive, Map<String, String> pairedValues) {
        var keys = new LinkedHashSet<>(contextFields);
        keys.addAll(term.spellings());
        run(keys, term, new AutoSearch(term, term.textPattern(caseSensitive)), pairedValues);
    }

    private record SearchTerm(String raw, List<String> spellings) {
        static SearchTerm of(String raw) {
            return of(raw, List.of());
        }

        static SearchTerm of(String raw, List<FieldExtractor.Pair> context) {
            var spellings = new LinkedHashSet<String>();
            spellings.add(raw);
            String utf8 = FieldExtractor.decodeFormComponent(raw);
            spellings.add(utf8);
            spellings.add(SearchEncoding.url(raw));
            spellings.add(SearchEncoding.html(raw));
            if (raw.indexOf('%') >= 0 && !context.isEmpty()) {
                var decodedByCharset = new HashMap<Charset, String>();
                decodedByCharset.put(StandardCharsets.UTF_8, utf8);
                for (var field : context) {
                    if (field.form == null) continue;
                    String decoded = decodedByCharset.computeIfAbsent(field.form.charset(),
                            charset -> FieldExtractor.decodeFormComponent(raw, charset));
                    if (decoded.equals(field.key) || decoded.equals(field.value)) spellings.add(decoded);
                }
            }
            return new SearchTerm(raw, List.copyOf(spellings));
        }

        boolean matches(FieldExtractor.Pair field) {
            return spellings.contains(field.value) || field.form != null && spellings.contains(field.wireValue())
                    || field.kind == Kind.BODY
                        && SearchEncoding.matchesDecoded(field.value, field.form == null, spellings::contains);
        }

        boolean names(FieldExtractor.Pair pair, FieldId field) {
            return pair.form != null && spellings.contains(pair.wireKey()) || matchesName(spellings, field);
        }

        String containedIn(String value) {
            for (String spelling : spellings) {
                if (!isGeneric(spelling) && value.contains(spelling)) return spelling;
            }
            return null;
        }

        Set<String> keysIn(List<FieldExtractor.Pair> context) {
            var keys = new LinkedHashSet<String>();
            for (var field : context) {
                if (!field.domAlias && matches(field)) keys.add(field.key);
            }
            return keys;
        }

        Pattern textPattern(boolean caseSensitive) {
            if (spellings.size() == 1) return literalPattern(raw, caseSensitive);
            String alternatives = spellings.stream().filter(spelling -> !spelling.isBlank()).map(Pattern::quote)
                    .collect(java.util.stream.Collectors.joining("|"));
            return Pattern.compile(alternatives,
                    caseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        }

        Predicate<String> similarValues() {
            Predicate<String> format = DiscoveryValues.similarTo(raw);
            for (String spelling : spellings.subList(1, spellings.size())) {
                var candidate = DiscoveryValues.similarTo(spelling);
                if (candidate == DiscoveryValues.NO_COMPARISON) continue;
                format = format == DiscoveryValues.NO_COMPARISON ? candidate : format.or(candidate);
            }
            return format;
        }
    }

    private record AutoSearch(SearchTerm term, Pattern needle) {}

    private void run(Set<String> seedKeys, SearchTerm seedValue, AutoSearch auto, Map<String, String> pairedValues) {
        Set<FieldId> seenKeys = new HashSet<>();
        Set<String> seenValues = new HashSet<>();
        if (seedValue != null) {
            seenValues.addAll(seedValue.spellings());
        }
        Predicate<String> similar = seedValue == null ? DiscoveryValues.NO_COMPARISON : seedValue.similarValues();
        Predicate<String> comparable = seedValue != null
                && seedValue.spellings().stream().anyMatch(DiscoveryValues::calendarDate)
                ? DiscoveryValues::calendarDate : similar;
        Map<String, String> nextValues = new LinkedHashMap<>(pairedValues);
        List<Hit> siblingHits = new ArrayList<>();

        int total = totalEntries;
        int index = 0;
        for (var records = entries.iterator(); !stop() && records.hasNext();) {
            if ((index & 31) == 0) {
                if (index > 0) java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
                sink.progress("Scanning records", index, total);
            }
            index++;
            CapturedEntry e = records.next();
            if (e == null) continue;
            if (direction != Direction.RESPONSE) {
                var message = Util.requestText(e.requestResponse());
                scanSource(e, REQ, message, seedKeys, seedValue, nextValues, siblingHits, auto, comparable);
            }
            if (direction != Direction.REQUEST && e.requestResponse().response() != null && !stop()) {
                var message = Util.responseText(e.requestResponse());
                scanSource(e, RESP, message, seedKeys, seedValue, nextValues, siblingHits, auto, comparable);
            }
        }
        sink.progress("Scanning records", index, total);

        if (depth > 0 && !stop()) {
            for (FieldId field : byKey.keySet()) {
                if (matchesName(seedKeys, field)) seenKeys.add(field);
            }
            if (seedValue != null && seedValue.spellings().stream().anyMatch(ExtractEngine::isDistinctive)) {
                expandMatchedFields(seedKeys, seedValue, seenKeys, nextValues, comparable);
            }
        }

        for (int level = 1; level <= depth && !nextValues.isEmpty() && !stop(); level++) {
            Map<FieldId, Map<String, String>> links = new LinkedHashMap<>();
            for (var candidate : nextValues.entrySet()) {
                if (stop()) return;
                if (!seenValues.add(candidate.getKey())) continue;
                var keys = new LinkedHashSet<FieldId>();
                for (Hit hit : byValue.getOrDefault(candidate.getKey(), List.of())) {
                    keys.add(fieldId(hit.pair));
                    if (keys.size() > MAX_FANOUT) break;
                }
                if (keys.size() > MAX_FANOUT) continue;
                for (FieldId key : keys) {
                    if (seenKeys.contains(key) && !candidate.getKey().equals(candidate.getValue())) continue;
                    if (links.size() >= MAX_FRONTIER && !links.containsKey(key)) {
                        discoveryLimited = true;
                        continue;
                    }
                    links.computeIfAbsent(key, ignored -> new LinkedHashMap<>())
                            .putIfAbsent(candidate.getKey(), candidate.getValue());
                }
            }

            nextValues = new LinkedHashMap<>();
            seenKeys.addAll(links.keySet());
            int[] score = {Math.max(DERIVED[0] - 10 * (level - 1), 5),
                           Math.max(DERIVED[1] - 10 * (level - 1), 5)};
            String depthLabel = level > 1 ? " (level " + level + ")" : "";
            int done = 0;
            for (var link : links.entrySet()) {
                if (stop()) return;
                FieldId key = link.getKey();
                sink.progress("Finding related fields", done++, links.size());
                var hits = byKey.getOrDefault(key, List.of());
                boolean expand = level < depth && !hits.isEmpty() && DiscoveryValues.usefulField(hits.get(0).pair)
                        && link.getValue().entrySet().stream().anyMatch(evidence -> !evidence.getKey().equals(evidence.getValue()))
                        && distinctValues(hits) <= MAX_KEY_VALUES;
                var formats = expand ? link.getValue().entrySet().stream()
                        .filter(evidence -> !evidence.getKey().equals(evidence.getValue()))
                        .map(evidence -> DiscoveryValues.calendarDate(evidence.getKey())
                                ? (Predicate<String>) DiscoveryValues::calendarDate : DiscoveryValues.similarTo(evidence.getKey()))
                        .filter(format -> format != DiscoveryValues.NO_COMPARISON).toList() : List.<Predicate<String>>of();
                for (Hit hit : hits) {
                    if (stop()) return;
                    String value = hit.linkValue;
                    String origin = link.getValue().get(value);
                    if (origin != null) {
                        String reason = origin.equals(value) ? "Field name used as value" + depthLabel + " ← " + origin
                                : "Related field" + depthLabel + " ← " + origin + "=" + shorten(value);
                        emitStructured(hit.entry, hit.src, hit.pair, score, reason, true, hit.pair.wireValue());
                    } else if (expand && DiscoveryValues.linkableValue(value) && (seedValue == null
                            || comparable.test(value) || formats.stream().anyMatch(format -> format.test(value)))) {
                        // Other values may help verify a later link. They do not become results on their own.
                        collectValue(nextValues, seenValues, value, hit.pair.key);
                    }
                }
            }
        }

        if (siblings) {
            sink.progress("Neighboring fields", 0, 1);
            for (Hit h : siblingHits) {
                if (stop()) {
                    return;
                }
                emitStructured(h.entry, h.src, h.pair, SIBLING, "Neighboring field", true, h.pair.wireValue());
            }
        }
    }

    private void scanSource(CapturedEntry e, String src, Util.MessageText message, Set<String> seedKeys,
                            SearchTerm seedValue, Map<String, String> nextValues, List<Hit> siblingHits, AutoSearch auto,
                            Predicate<String> comparable) {
        boolean directHit = false;
        boolean response = src.equals(RESP);
        var exchange = e.requestResponse();
        var http = response ? exchange.response() : exchange.request();
        List<FieldExtractor.Pair> pairs = HttpSearchFields.collect(http, response, message.searchFields());
        var endpoint = collapseRepeated && depth > 0 ? e.key() : null;
        Map<Integer, String> hitObjs = null;

        for (FieldExtractor.Pair p : pairs) {
            if (stop()) {
                return;
            }
            FieldId field = fieldId(p);
            boolean seeded = matchesName(seedKeys, field) || p.form != null && seedKeys.contains(p.wireKey());
            boolean named = seeded && (seedValue == null || auto != null && auto.term().names(p, field));
            if (p.value.isBlank()) {
                if (named) {
                    emitStructured(e, src, p, KEY, "Field match", false, p.wireKey());
                    directHit = true;
                }
                continue;
            }
            boolean protectedValue = HttpSearchFields.protectedValue(p);
            boolean boundedField = depth > 0 && p.key.length() <= 256 && p.value.length() <= 2000;
            boolean discoverable = boundedField && HttpSearchFields.indexForDiscovery(p, protectedValue);
            if (discoverable) {
                indexField(e, src, p, endpoint, nextValues.keySet());
            }

            boolean exact = seedValue != null && seedValue.matches(p);
            // An ID-only control can corroborate the same key elsewhere. A DOM alias cannot establish a field.
            if (exact && (discoverable || boundedField && p.domId && !p.domAlias)
                    && matchedFields.size() < MAX_FRONTIER) matchedFields.add(field);
            String partialMatch = !exact && !named && seedValue != null && partial && p.kind != Kind.COOKIE
                    ? seedValue.containedIn(p.value) : null;
            if (exact || named) {
                emitStructured(e, src, p, exact && seeded ? KEY_AND_VALUE : exact ? VALUE : KEY,
                        exact && seeded ? "Field and value match" : exact ? "Value match" : "Field match",
                        false, exact ? p.wireValue() : p.wireKey());
                directHit = true;
            } else if (partialMatch != null) {
                emitStructured(e, src, p, VALUE_PART, "Partial value match", false,
                        p.form == null ? partialMatch : p.wireValue());
                directHit = true;
            } else if (discoverable && seedValue != null && (!variantLimitReached || seeded)
                    && comparableValue(p, comparable) && DiscoveryValues.usefulField(p)) {
                if (seeded) showFieldVariant(e, src, p, true);
                else rememberVariant(e, src, p);
            }
            if (depth > 0 && named && canFollowNamedField(p)) {
                String linked = linkValue(p);
                if (DiscoveryValues.linkableValue(linked)) collectValue(nextValues, Set.of(), linked, p.key);
            }
            if (siblings && exact && p.objId >= 0) hitObjs = addObj(hitObjs, p.objId, p.key);
        }

        if (!directHit && auto != null) {
            textMatch(e, src, message, auto.needle());
        } else if (!directHit && partial && seedValue != null) {
            String match = seedValue.containedIn(message.searchable());
            if (match != null) emit(e, src, "", match, VALUE_FREE, "Value in plain text");
        }

        if (hitObjs != null) {
            for (FieldExtractor.Pair p : pairs) {
                String holder = hitObjs.get(p.objId);
                if (holder != null && !p.domId && !p.key.equals(holder) && siblingHits.size() < MAX_ROWS
                        && p.key.length() <= 256 && p.value.length() <= 2000 && !p.value.isBlank()) {
                    siblingHits.add(new Hit(e, src, p));
                }
            }
        }
    }


    private void expandMatchedFields(Set<String> seedKeys, SearchTerm searched, Set<FieldId> seenKeys,
                                     Map<String, String> nextValues, Predicate<String> comparable) {
        var bodyNames = new LinkedHashSet<String>();
        for (var field : matchedFields) {
            if (field.kind() == Kind.BODY) {
                bodyNames.add(field.name());
                bodyNames.add(SearchEncoding.url(field.name()));
                bodyNames.add(SearchEncoding.html(field.name()));
            }
        }
        Predicate<FieldId> knownField = field -> matchedFields.contains(field) || matchesName(seedKeys, field)
                || field.kind() == Kind.BODY && matchesName(bodyNames, field);
        var candidates = new LinkedHashSet<>(matchedFields);
        for (var field : byKey.keySet()) {
            if (knownField.test(field)) candidates.add(field);
        }

        if (variantLimitReached) {
            if (!candidates.isEmpty() || !searched.spellings().containsAll(seedKeys)) {
                recoverFieldVariants(knownField, seedKeys, searched, comparable);
            }
        } else {
            for (var hit : variantHits) {
                if (stop()) return;
                var field = fieldId(hit.pair);
                if (knownField.test(field)) showFieldVariant(hit.entry, hit.src, hit.pair, matchesName(seedKeys, field));
            }
        }
        int count = 0;
        for (FieldId field : candidates) {
            if (stop()) return;
            if (++count > MAX_FRONTIER) {
                discoveryLimited = true;
                break;
            }
            var hits = byKey.getOrDefault(field, List.of());
            if (hits.isEmpty()) continue;
            var example = hits.get(0).pair;
            String name = linkSpelling(example, example.key);
            if (DiscoveryValues.linkableValue(name)) {
                collectValue(nextValues, Set.of(), name, name);
            }
            boolean contextual = matchesName(seedKeys, field);
            boolean useful = DiscoveryValues.usefulField(example);
            boolean propagate = contextual && useful || distinctValues(hits) <= MAX_KEY_VALUES;

            Set<String> variants = new HashSet<>();
            for (Hit hit : hits) {
                if (stop()) return;
                String value = hit.linkValue;
                if (!variantOf(hit.pair, searched, comparable)) continue;
                if (!propagate) continue;
                if (!variants.contains(value) && variants.size() >= MAX_VARIANT_VALUES) {
                    discoveryLimited = true;
                    continue;
                }
                boolean first = variants.add(value);
                if (!useful) {
                    if (first && corroboratedOutside(field, value)) {
                        collectValue(nextValues, Set.of(), value, hit.pair.key);
                    }
                    continue;
                }
                if (first) collectValue(nextValues, Set.of(), value, hit.pair.key);
            }
            if (useful) seenKeys.add(field);
        }
    }

    private void recoverFieldVariants(Predicate<FieldId> knownField, Set<String> seedKeys,
                                      SearchTerm searched, Predicate<String> comparable) {
        int scanned = 0;
        for (var records = entries.iterator(); !stop() && records.hasNext();) {
            if ((scanned & 31) == 0) {
                if (scanned > 0) java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
                sink.progress("Checking matching fields across traffic", scanned, totalEntries);
            }
            var entry = records.next();
            scanned++;
            if (entry == null) continue;
            var exchange = entry.requestResponse();
            if (direction != Direction.RESPONSE) {
                recoverFieldVariants(entry, REQ, HttpSearchFields.collect(exchange, true),
                        knownField, seedKeys, searched, comparable);
            }
            if (direction != Direction.REQUEST && exchange.response() != null && !stop()) {
                recoverFieldVariants(entry, RESP, HttpSearchFields.collect(exchange, false),
                        knownField, seedKeys, searched, comparable);
            }
        }
    }

    private void recoverFieldVariants(CapturedEntry entry, String side, List<FieldExtractor.Pair> fields,
                                      Predicate<FieldId> knownField, Set<String> seedKeys,
                                      SearchTerm searched, Predicate<String> comparable) {
        for (var pair : fields) {
            if (stop()) return;
            var field = fieldId(pair);
            if (!matchesName(seedKeys, field) && !(pair.form != null && seedKeys.contains(pair.wireKey()))
                    && knownField.test(field) && HttpSearchFields.indexForDiscovery(pair, HttpSearchFields.protectedValue(pair))
                    && DiscoveryValues.usefulField(pair) && variantOf(pair, searched, comparable)) {
                showFieldVariant(entry, side, pair, matchesName(seedKeys, field));
            }
        }
    }

    private boolean variantOf(FieldExtractor.Pair pair, SearchTerm searched, Predicate<String> comparable) {
        return !searched.matches(pair)
                && (!partial || searched.containedIn(pair.value) == null)
                && comparableValue(pair, comparable);
    }

    private static boolean comparableValue(FieldExtractor.Pair pair, Predicate<String> comparable) {
        return comparable != DiscoveryValues.NO_COMPARISON && (comparable.test(pair.value)
                || pair.kind == Kind.BODY && SearchEncoding.matchesDecoded(pair.value, pair.form == null, comparable));
    }

    private void rememberVariant(CapturedEntry entry, String side, FieldExtractor.Pair pair) {
        int size = retainedCharacters(pair);
        if (variantHits.size() >= MAX_VARIANT_HITS || variantCharacters + size > MAX_VARIANT_CHARACTERS) {
            variantLimitReached = true;
            variantHits.clear();
            return;
        }
        variantHits.add(new Hit(entry, side, pair));
        variantCharacters += size;
    }

    private void showFieldVariant(CapturedEntry entry, String side, FieldExtractor.Pair pair, boolean contextual) {
        emitStructured(entry, side, pair, contextual ? CONTEXT_VARIANT : ALIAS_VARIANT,
                contextual ? "Similar value in selected field" : "Similar value in matched field", true, pair.wireValue());
    }

    private boolean corroboratedOutside(FieldId field, String value) {
        for (Hit evidence : byValue.getOrDefault(value, List.of())) {
            if (stop()) return false;
            if (!field.equals(fieldId(evidence.pair)) && DiscoveryValues.usefulField(evidence.pair)) return true;
        }
        return false;
    }

    private static boolean canFollowNamedField(FieldExtractor.Pair field) {
        return field.key.length() <= 256 && field.value.length() <= 2000 && DiscoveryValues.usefulField(field)
                && (field.domId || HttpSearchFields.indexForDiscovery(field, HttpSearchFields.protectedValue(field)));
    }

    private static String linkValue(FieldExtractor.Pair field) {
        return linkSpelling(field, field.value);
    }

    private static String linkSpelling(FieldExtractor.Pair field, String spelling) {
        if (field.kind != Kind.BODY) return spelling;
        String decoded = field.form == null ? SearchEncoding.url(spelling) : spelling;
        return decoded.equals(spelling) ? SearchEncoding.html(spelling) : decoded;
    }

    private static FieldId fieldId(FieldExtractor.Pair pair) {
        return new FieldId(pair.kind, pair.kind == Kind.HEADER ? pair.key.toLowerCase(Locale.ROOT) : pair.key);
    }

    private static boolean matchesName(Collection<String> names, FieldId field) {
        if (names.isEmpty()) return false;
        if (names.contains(field.name())) return true;
        return switch (field.kind()) {
            case HEADER -> names.stream().anyMatch(field.name()::equalsIgnoreCase);
            case BODY -> SearchEncoding.matchesDecoded(field.name(), true, names::contains);
            case COOKIE -> false;
        };
    }

    private void indexField(CapturedEntry entry, String side, FieldExtractor.Pair pair,
                            CapturedEntry.Key endpoint, Set<String> knownLinks) {
        if (indexLimited && endpoint == null && (knownLinks.isEmpty() || knownLinkHits >= MAX_KNOWN_LINK_HITS)) return;
        String linked = linkValue(pair);
        var key = endpoint == null ? null : new IndexedField(endpoint, side, fieldId(pair), linked);
        var existing = key == null ? null : indexed.get(key);
        if (existing != null) {
            if (!existing.entry.hasResponse() && entry.hasResponse()) existing.entry = entry;
            return;
        }
        int size = retainedCharacters(pair) + (linked.equals(pair.value) ? 0 : linked.length());
        if (indexLimited || indexedPairs >= MAX_DISCOVERY_PAIRS || indexedCharacters >= MAX_DISCOVERY_CHARACTERS) {
            indexLimited = true;
            discoveryLimited = true;
            // Keep room for exact links established by the selected message or already scanned fields.
            if (!knownLinks.contains(linked) || knownLinkHits >= MAX_KNOWN_LINK_HITS
                    || knownLinkCharacters + size > MAX_KNOWN_LINK_CHARACTERS) return;
            knownLinkHits++;
            knownLinkCharacters += size;
        } else {
            indexedPairs++;
            indexedCharacters += size;
        }
        var hit = new Hit(entry, side, pair, linked);
        if (key != null) indexed.put(key, hit);
        byKey.computeIfAbsent(fieldId(pair), ignored -> new ArrayList<>()).add(hit);
        if (isDistinctive(linked)) {
            byValue.computeIfAbsent(linked, ignored -> new ArrayList<>()).add(hit);
        }
    }

    private static int retainedCharacters(FieldExtractor.Pair pair) {
        int size = pair.key.length() + pair.value.length();
        if (pair.wireKey() != pair.key) size += pair.wireKey().length();
        if (pair.wireValue() != pair.value) size += pair.wireValue().length();
        return size;
    }

    private static int distinctValues(List<Hit> hits) {
        Set<String> vals = new HashSet<>();
        for (Hit h : hits) {
            if (vals.add(h.linkValue) && vals.size() > MAX_KEY_VALUES) {
                break;
            }
        }
        return vals.size();
    }

    private static Map<Integer, String> addObj(Map<Integer, String> map, int id, String key) {
        if (map == null) {
            map = new HashMap<>();
        }
        map.putIfAbsent(id, key);
        return map;
    }

    private static void collectValue(Map<String, String> out, Set<String> seen, String value, String key) {
        if (out.size() < MAX_VALUES_PER_LEVEL && isDistinctive(value) && !seen.contains(value)) {
            out.putIfAbsent(value, key);
        }
    }

    static boolean isGeneric(String v) {
        if (v == null || v.length() < 3 || v.isBlank()) {
            return true;
        }
        switch (v.toLowerCase()) {
            case "true": case "false": case "null": case "undefined": case "none":
                return true;
            default:
                return false;
        }
    }

    static boolean isDistinctive(String v) {
        if (v == null) {
            return false;
        }
        int n = v.length();
        if (n < 3 || n > 2000 || v.isBlank()) {
            return false;
        }
        if (n < 5 && v.chars().noneMatch(Character::isLetter)) {
            return false;
        }
        switch (v.toLowerCase()) {
            case "true": case "false": case "null": case "undefined": case "none": case "0.0":
                return false;
            default:
                return true;
        }
    }

    private void emit(CapturedEntry e, String src, String key, String value, int[] score, String reason) {
        emit(e, src, key, value, score, reason, false);
    }

    private void emit(CapturedEntry e, String src, String key, String value, int[] score, String reason, boolean related) {
        emit(e, src, key, value, score, reason, related, value);
    }

    private void emit(CapturedEntry e, String src, String key, String value, int[] score,
                      String reason, boolean related, String matchedText) {
        emit(e, src, key, value, score, reason, related, matchedText, Kind.BODY);
    }

    private void emitStructured(CapturedEntry entry, String side, FieldExtractor.Pair field,
                                int[] score, String reason, boolean related, String match) {
        boolean masked = HttpSearchFields.protectedValue(field);
        String area = switch (field.kind) {
            case BODY -> "";
            case HEADER -> " · Header";
            case COOKIE -> side.equals(RESP) ? " · Set-Cookie" : " · Cookie";
        };
        String wireValue = !masked && (field.form != null || !field.value.equals(field.wireValue()))
                ? field.wireValue() : null;
        emit(entry, side, field.key, masked ? "Hidden" : field.value, wireValue, score, reason + area,
                related, masked || !fitsEditorSearch(match) ? field.wireKey() : match, field.kind);
    }

    private void emit(CapturedEntry e, String src, String key, String value, int[] score,
                      String reason, boolean related, String matchedText, Kind kind) {
        emit(e, src, key, value, null, score, reason, related, matchedText, kind);
    }

    private void emit(CapturedEntry e, String src, String key, String value, String wireValue, int[] score,
                      String reason, boolean related, String matchedText, Kind kind) {
        if (stop()) return;
        boolean same = !sourceEndpoint.isEmpty()
                && CapturedEntry.endpoint(e.requestResponse().request()).equals(sourceEndpoint);
        String preview = clip(value);
        String displayKey = key.length() > 256 ? key.substring(0, 256) + "…" : key;
        Object location = collapseRepeated && !value.isEmpty() ? e.key() : e;
        var dedup = new MatchKey(location, src,
                new FieldId(kind, kind == Kind.HEADER ? displayKey.toLowerCase(Locale.ROOT) : displayKey),
                value.length(), value.hashCode(), preview);
        var previous = emitted.get(dedup);
        if (previous != null) {
            if (!previous.entry.latest().hasResponse() && e.latest().hasResponse()) {
                var complete = previous.withExchange(e.latest(), wireValue == null ? preview : clipWire(wireValue),
                        editorSearch(matchedText, key));
                emitted.put(dedup, complete);
                sink.row(complete);
            }
            return;
        }
        if (emitted.size() >= MAX_ROWS) {
            truncated = true;
            return;
        }
        var row = new ResultRow(emitted.size(), same ? score[0] : score[1], e.userCode(),
                e.requestResponse().request().url(), src, displayKey, wireValue == null ? preview : clipWire(wireValue),
                reason + (same ? " · same endpoint" : ""), e, related, editorSearch(matchedText, key));
        emitted.put(dedup, row);
        sink.row(row);
    }

    private boolean stop() {
        return truncated || sink.cancelled();
    }

    private static String editorSearch(String value, String key) {
        if (fitsEditorSearch(value)) return value;
        return fitsEditorSearch(key) ? key : "";
    }

    private static boolean fitsEditorSearch(String text) {
        return text.length() <= 512 && !text.isBlank()
                && text.indexOf('\n') < 0 && text.indexOf('\r') < 0;
    }

    private static String clip(String s) {
        if (s != null && s.length() > MAX_VALUE_CHARS) {
            return oneLine(s.substring(0, MAX_VALUE_CHARS)) + "… (+" + (s.length() - MAX_VALUE_CHARS) + " characters)";
        }
        return oneLine(s);
    }

    private static String clipWire(String value) {
        if (value.length() <= MAX_VALUE_CHARS) return value;
        return value.substring(0, MAX_VALUE_CHARS) + "… (+" + (value.length() - MAX_VALUE_CHARS) + " characters)";
    }

    private static String shorten(String s) {
        String t = oneLine(s);
        return t.length() > 40 ? t.substring(0, 40) + "…" : t;
    }

    private static String oneLine(String s) {
        if (s == null) {
            return "";
        }
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i)) && s.charAt(i) != ' ') {
                return s.replaceAll("\\s+", " ").trim();
            }
        }
        return s.trim();
    }
}
