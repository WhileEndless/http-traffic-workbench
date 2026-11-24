package trafficworkbench;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Locale;

record CapturedEntry(String userCode, String method, String path, short statusCode,
                     HttpRequestResponse requestResponse, long time, TrafficSource source, int listenerPort,
                     boolean annotated, Cache cache) {
    static CapturedEntry of(String label, HttpRequestResponse exchange) {
        return of(label, exchange, System.currentTimeMillis());
    }

    static CapturedEntry of(String label, HttpRequestResponse exchange, long time) {
        return of(label, exchange, time, TrafficSource.ARCHIVE, 0, false);
    }

    static CapturedEntry of(String label, HttpRequestResponse exchange, long time, TrafficSource source,
                            int listenerPort, boolean annotated) {
        var request = exchange.request();
        short status = exchange.response() == null ? 0 : exchange.response().statusCode();
        return new CapturedEntry(label, request.method(), request.pathWithoutQuery(), status, exchange, time, source, listenerPort, annotated, new Cache());
    }

    static String endpoint(HttpRequest request) {
        var service = request.httpService();
        return service.secure() + "|" + service.host().toLowerCase(Locale.ROOT) + "|" + service.port()
                + "|" + request.method() + "|" + request.pathWithoutQuery();
    }

    Key key() {
        var service = requestResponse.request().httpService();
        return new Key(service.host().toLowerCase(Locale.ROOT), service.port(), service.secure(), userCode, method, path, source);
    }

    boolean hasResponse() {
        return requestResponse.response() != null;
    }

    void awaitCompletion() {
        cache.awaitingResponse = true;
    }

    boolean awaitingResponse() {
        return cache.awaitingResponse && cache.completed == null;
    }

    void attachCompletion(CapturedEntry completed) {
        cache.completed = completed;
    }

    CapturedEntry latest() {
        var completed = cache.completed;
        return completed == null ? this : completed;
    }

    int size() {
        return requestResponse.request().toByteArray().length()
                + (requestResponse.response() == null ? 0 : requestResponse.response().toByteArray().length());
    }

    boolean matches(CapturedEntry other) {
        if (contentHash() != other.contentHash()) {
            return false;
        }
        var ours = requestResponse;
        var theirs = other.requestResponse;
        if (!java.util.Arrays.equals(ours.request().toByteArray().getBytes(), theirs.request().toByteArray().getBytes())) {
            return false;
        }
        if (ours.response() == null || theirs.response() == null) {
            return ours.response() == null && theirs.response() == null;
        }
        return java.util.Arrays.equals(ours.response().toByteArray().getBytes(), theirs.response().toByteArray().getBytes());
    }

    long contentHash() {
        if (!cache.hashed) {
            cache.hash = Util.contentHash(requestResponse);
            cache.hashed = true;
        }
        return cache.hash;
    }

    record Key(String host, int port, boolean secure, String user, String method, String path, TrafficSource source) {}

    private static final class Cache {
        private volatile CapturedEntry completed;
        private volatile boolean awaitingResponse;
        private volatile long hash;
        private volatile boolean hashed;
    }
}
