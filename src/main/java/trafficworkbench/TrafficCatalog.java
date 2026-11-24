package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.organizer.Organizer;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Objects;
import java.util.Iterator;
import java.util.Spliterators;
import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.StreamSupport;
import java.util.Set;
import java.util.stream.Stream;

final class TrafficCatalog {
    private static final Method ORGANIZER_ITEMS = organizerMethod();

    private final MontoyaApi api;
    private final CollectorStore store;

    TrafficCatalog(MontoyaApi api, CollectorStore store) {
        this.api = api;
        this.store = store;
    }

    Stream<CapturedEntry> stream(Set<TrafficSource> selected, String prefix) {
        return stream(selected, prefix, "");
    }

    Stream<CapturedEntry> stream(Set<TrafficSource> selected, String prefix, String host) {
        Stream<CapturedEntry> project = Stream.empty();
        for (TrafficSource source : TrafficSource.values()) {
            if (selected.contains(source) && !source.toolTraffic() && source != TrafficSource.ARCHIVE) {
                project = Stream.concat(project, deferred(() -> availableSource(source, prefix, host)));
            }
        }
        Stream<CapturedEntry> archive = store.all().stream().filter(entry -> selected.contains(entry.source()));
        return Stream.concat(project, archive).filter(Objects::nonNull)
                .filter(entry -> matchesHost(host, entry.requestResponse().request().httpService()));
    }

    static boolean matchesHost(String host, HttpService service) {
        return host.isEmpty() || service != null && host.equalsIgnoreCase(service.host());
    }

    static Stream<CapturedEntry> includeSelected(Stream<CapturedEntry> records, CapturedEntry selected) {
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

    private Stream<CapturedEntry> availableSource(TrafficSource source, String prefix, String host) {
        try {
            return projectSource(source, prefix, host);
        } catch (RuntimeException ex) {
            api.logging().logToError(source.label + " could not be opened (" + ex.getClass().getSimpleName() + ").");
            return Stream.empty();
        }
    }

    private Stream<CapturedEntry> projectSource(TrafficSource source, String prefix, String host) {
        return switch (source) {
            case PROXY -> proxyHistory(host).map(item -> {
                var request = ProxyMessages.request(item);
                if (request == null || request.httpService() == null || !matchesHost(host, request.httpService())) return null;
                var time = item.time();
                var exchange = HttpRequestResponse.httpRequestResponse(request, ProxyMessages.response(item));
                return record(exchange, item.annotations(), time == null ? 0 : time.toInstant().toEpochMilli(),
                        source, item.listenerPort(), prefix);
            });
            case SITE_MAP -> api.siteMap().requestResponses().stream()
                    .map(exchange -> record(exchange, exchange.annotations(), 0, source, 0, prefix));
            case FINDINGS -> api.siteMap().issues().stream().flatMap(issue -> issue.requestResponses().stream())
                    .map(exchange -> record(exchange, exchange.annotations(), 0, source, 0, prefix));
            case ORGANIZER -> organizerItems().map(exchange -> record(exchange, exchange.annotations(), 0, source, 0, prefix));
            default -> Stream.empty();
        };
    }

    private Stream<burp.api.montoya.proxy.ProxyHttpRequestResponse> proxyHistory(String host) {
        var proxy = api.proxy();
        if (host.isEmpty()) return proxy.history().stream();
        return proxy.history(item -> {
            var service = item.httpService();
            if (service != null) return matchesHost(host, service);
            var request = ProxyMessages.request(item);
            return request != null && matchesHost(host, request.httpService());
        }).stream();
    }

    static CapturedEntry record(HttpRequestResponse exchange, Annotations annotations, long time,
                                TrafficSource source, int listener, String prefix) {
        if (exchange == null || exchange.request() == null || exchange.request().httpService() == null) return null;
        String notes = annotations == null ? null : annotations.notes();
        String marker = prefix + ": ";
        String label = notes == null || notes.isEmpty() ? "" : notes.lines()
                .filter(line -> line.startsWith(marker)).reduce((first, last) -> last)
                .map(line -> line.substring(marker.length())).orElse("");
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
