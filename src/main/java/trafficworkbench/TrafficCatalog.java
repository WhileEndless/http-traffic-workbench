package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.organizer.Organizer;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Iterator;
import java.util.Spliterators;
import java.util.Spliterator;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.StreamSupport;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

final class TrafficCatalog {
    private static final Method ORGANIZER_ITEMS = organizerMethod();

    private final MontoyaApi api;
    private final CollectorStore store;

    TrafficCatalog(MontoyaApi api, CollectorStore store) {
        this.api = api;
        this.store = store;
    }

    record UserCount(String label, int records) {}
    record Users(List<UserCount> entries, boolean proxyUnavailable) {}

    Users users(CaptureProfile profile, BooleanSupplier cancelled) {
        var counts = new TreeMap<String, Integer>();
        boolean proxyUnavailable = false;
        try {
            for (var item : api.proxy().history()) {
                if (cancelled.getAsBoolean()) break;
                var annotations = item.annotations();
                if (annotations == null) continue;
                String label = UserLabeler.readNote(annotations.notes(), profile);
                if (!label.isEmpty()) counts.merge(label, 1, Integer::sum);
            }
        } catch (RuntimeException ignored) {
            proxyUnavailable = true;
        }
        for (var entry : store.all()) {
            if (cancelled.getAsBoolean()) break;
            if (!entry.userCode().isEmpty()) counts.merge(entry.userCode(), 1, Integer::sum);
        }
        return new Users(counts.entrySet().stream().map(entry -> new UserCount(entry.getKey(), entry.getValue()))
                .toList(), proxyUnavailable);
    }

    Stream<CapturedEntry> stream(Set<TrafficSource> selected, CaptureProfile profile) {
        return stream(selected, profile, "");
    }

    Stream<CapturedEntry> stream(Set<TrafficSource> selected, CaptureProfile profile, String host) {
        Stream<CapturedEntry> project = Stream.empty();
        for (TrafficSource source : TrafficSource.values()) {
            if (selected.contains(source) && !source.toolTraffic() && source != TrafficSource.ARCHIVE) {
                project = Stream.concat(project, deferred(() -> availableSource(source, profile, host)));
            }
        }
        Stream<CapturedEntry> archive = store.all().stream().filter(entry -> selected.contains(entry.source()));
        return Stream.concat(project, archive).filter(Objects::nonNull)
                .filter(entry -> matchesHost(host, entry.requestResponse().request().httpService()));
    }

    static boolean matchesHost(String host, HttpService service) {
        return host.isEmpty() || service != null && host.equalsIgnoreCase(service.host());
    }

    String selectedUser(CapturedEntry selected, CaptureProfile profile, BooleanSupplier cancelled) {
        if (selected == null || cancelled.getAsBoolean()) return "";
        if (!selected.userCode().isEmpty()) return selected.userCode();
        var exchange = selected.requestResponse();
        if (selected.source() == TrafficSource.PROXY) {
            try {
                String host = exchange.request().httpService().host();
                var nativeRow = new SessionAnchor(exchange, null, "")
                        .resolve(proxyHistory(host), cancelled).item();
                var annotations = nativeRow == null ? null : nativeRow.annotations();
                return annotations == null ? "" : UserLabeler.readNote(annotations.notes(), profile);
            } catch (RuntimeException ignored) {
                return "";
            }
        }

        String endpoint = CapturedEntry.endpoint(exchange.request());
        String label = null;
        for (var entry : store.all()) {
            if (cancelled.getAsBoolean()) return "";
            if (entry.source() != selected.source() || !endpoint.equals(CapturedEntry.endpoint(entry.requestResponse().request()))
                    || !selected.matches(entry)) continue;
            if (entry.userCode().isEmpty() || label != null && !label.equals(entry.userCode())) return "";
            label = entry.userCode();
        }
        return Objects.toString(label, "");
    }

    static Stream<CapturedEntry> includeSelected(Stream<CapturedEntry> records, CapturedEntry selected) {
        if (selected.source() == TrafficSource.PROXY) {
            // Use native history annotations whenever the context exchange is already present.
            var found = new java.util.concurrent.atomic.AtomicBoolean();
            String endpoint = CapturedEntry.endpoint(selected.requestResponse().request());
            var nativeRecords = records.peek(entry -> {
                if (!found.get() && entry.source() == TrafficSource.PROXY
                        && endpoint.equals(CapturedEntry.endpoint(entry.requestResponse().request())) && selected.matches(entry)) {
                    found.set(true);
                }
            });
            return Stream.concat(nativeRecords, Stream.of(selected).filter(entry -> !found.get()));
        }
        // Substitute one existing copy while retaining repeated traffic and native metadata on other records.
        var pendingDuplicate = new java.util.concurrent.atomic.AtomicBoolean(true);
        var key = selected.key();
        return Stream.concat(Stream.of(selected), records.filter(entry -> {
            if (pendingDuplicate.get() && key.equals(entry.key())
                    && (selected.listenerPort() == 0 || selected.listenerPort() == entry.listenerPort())
                    && selected.annotated() == entry.annotated() && selected.matches(entry)) {
                return !pendingDuplicate.getAndSet(false);
            }
            return true;
        }));
    }

    private static Stream<CapturedEntry> deferred(Supplier<Stream<CapturedEntry>> records) {
        return StreamSupport.stream(new Spliterators.AbstractSpliterator<>(Long.MAX_VALUE, Spliterator.ORDERED) {
            private Iterator<CapturedEntry> iterator;

            @Override public boolean tryAdvance(Consumer<? super CapturedEntry> consumer) {
                if (iterator == null) iterator = records.get().iterator();
                if (!iterator.hasNext()) return false;
                consumer.accept(iterator.next());
                return true;
            }
        }, false);
    }

    private Stream<CapturedEntry> availableSource(TrafficSource source, CaptureProfile profile, String host) {
        try {
            return projectSource(source, profile, host);
        } catch (RuntimeException ex) {
            api.logging().logToError(source.label + " could not be opened (" + ex.getClass().getSimpleName() + ").");
            return Stream.empty();
        }
    }

    private Stream<CapturedEntry> projectSource(TrafficSource source, CaptureProfile profile, String host) {
        return switch (source) {
            case PROXY -> proxyHistory(host).stream().map(item -> {
                var request = ProxyMessages.request(item);
                if (request == null || request.httpService() == null || !matchesHost(host, request.httpService())) return null;
                var time = item.time();
                var exchange = HttpRequestResponse.httpRequestResponse(request, ProxyMessages.response(item));
                return record(exchange, item.annotations(), time == null ? 0 : time.toInstant().toEpochMilli(),
                        source, item.listenerPort(), profile);
            });
            case SITE_MAP -> api.siteMap().requestResponses().stream()
                    .map(exchange -> record(exchange, exchange.annotations(), 0, source, 0, profile));
            case FINDINGS -> api.siteMap().issues().stream().flatMap(issue -> issue.requestResponses().stream())
                    .map(exchange -> record(exchange, exchange.annotations(), 0, source, 0, profile));
            case ORGANIZER -> organizerItems().map(exchange -> record(exchange, exchange.annotations(), 0, source, 0, profile));
            default -> Stream.empty();
        };
    }

    private List<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory(String host) {
        var proxy = api.proxy();
        if (host.isEmpty()) return proxy.history();
        return proxy.history(item -> {
            var service = item.httpService();
            if (service != null) return matchesHost(host, service);
            var request = ProxyMessages.request(item);
            return request != null && matchesHost(host, request.httpService());
        });
    }

    static CapturedEntry record(HttpRequestResponse exchange, Annotations annotations, long time,
                                TrafficSource source, int listener, CaptureProfile profile) {
        if (exchange == null || exchange.request() == null || exchange.request().httpService() == null) return null;
        String notes = annotations == null ? null : annotations.notes();
        String label = UserLabeler.readNote(notes, profile);
        boolean annotated = annotations != null && ((notes != null && !notes.isBlank()) || annotations.hasHighlightColor());
        return CapturedEntry.of(label, exchange, time, source, listener, annotated);
    }

    private Stream<HttpRequestResponse> organizerItems() {
        if (ORGANIZER_ITEMS == null) return Stream.empty();
        try {
            Object result = ORGANIZER_ITEMS.invoke(api.organizer());
            return result instanceof Collection<?> items ? items.stream().filter(HttpRequestResponse.class::isInstance)
                    .map(HttpRequestResponse.class::cast) : Stream.empty();
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            api.logging().logToError("Organizer items could not be read.");
            return Stream.empty();
        }
    }

    private static Method organizerMethod() {
        try {
            return Organizer.class.getMethod("items");
        } catch (NoSuchMethodException ignored) {
            // The extension also runs on versions predating Organizer read access.
            return null;
        }
    }
}
