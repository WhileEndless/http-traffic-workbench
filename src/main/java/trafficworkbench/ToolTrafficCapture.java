package trafficworkbench;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.lang.ref.WeakReference;
import java.util.LinkedHashMap;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

final class ToolTrafficCapture implements HttpHandler {
    private static final int MAX_PENDING = 1_000;
    private static final int MAX_SAMPLE_BYTES = 2 * 1024 * 1024;

    private final Supplier<CaptureProfile.Compiled> settings;
    private final CollectorStore store;
    private final Executor executor;
    private final java.util.function.Consumer<RuntimeException> reportError;
    private final LinkedHashMap<MessageKey, WeakReference<CapturedEntry>> pending = new LinkedHashMap<>();

    ToolTrafficCapture(Supplier<CaptureProfile.Compiled> settings, CollectorStore store, Executor executor,
                       java.util.function.Consumer<RuntimeException> reportError) {
        this.settings = settings;
        this.store = store;
        this.executor = executor;
        this.reportError = reportError;
    }

    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        var profile = settings.get();
        if (!profile.settings().captureTools().isEmpty() && !profile.settings().successfulOnly()) {
            queue(profile, request.toolSource(), request.messageId(), request, null, request.annotations());
        }
        return RequestToBeSentAction.continueWith(request, request.annotations());
    }

    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        var profile = settings.get();
        if (!profile.settings().captureTools().isEmpty()
                && (!profile.settings().successfulOnly() || response.statusCode() >= 200 && response.statusCode() < 400)) {
            queue(profile, response.toolSource(), response.messageId(), response.initiatingRequest(),
                    response, response.annotations());
        }
        return ResponseReceivedAction.continueWith(response, response.annotations());
    }

    private void queue(CaptureProfile.Compiled profile, ToolSource tool, int id,
                       HttpRequest request, HttpResponse response, Annotations annotations) {
        if (profile.settings().captureTools().isEmpty() || request == null || tool == null) return;
        var source = TrafficSource.forTool(tool.toolType());
        if (!source.toolTraffic() && source != TrafficSource.ARCHIVE) source = TrafficSource.OTHER;
        if (!profile.settings().captureTools().contains(source)) return;
        final TrafficSource origin = source;
        long time = System.currentTimeMillis();
        executor.execute(() -> {
            try {
                capture(profile, id, request, response, annotations, origin, time);
            } catch (RuntimeException ex) {
                reportError.accept(ex);
            }
        });
    }

    private void capture(CaptureProfile.Compiled profile, int id, HttpRequest request, HttpResponse response,
                         Annotations annotations, TrafficSource origin, long time) {
        if (settings.get() != profile || !profile.matches(request)) return;
        long bodyBytes = (long) request.body().length() + (response == null ? 0 : response.body().length());
        if (bodyBytes > MAX_SAMPLE_BYTES) return;
        var exchange = HttpRequestResponse.httpRequestResponse(request, response);
        var entry = TrafficCatalog.record(exchange, annotations, time, origin, 0, profile.settings());
        if (entry == null) return;
        var key = new MessageKey(origin, id);
        if (response == null) {
            entry.awaitCompletion();
            store.add(entry);
            pending.put(key, new WeakReference<>(entry));
            if (pending.size() > MAX_PENDING) pending.remove(pending.keySet().iterator().next());
        } else {
            var previous = pending.remove(key);
            store.addCompleted(previous == null ? null : previous.get(), entry);
        }
    }
    private record MessageKey(TrafficSource source, int id) {}
}
