package trafficworkbench;

import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;

record SessionAnchor(HttpRequestResponse exchange, CaptureProfile.Source editorSide, String selection) {
    record Resolved(ProxyHttpRequestResponse item, HttpRequestResponse exchange, boolean ambiguous) {}

    Resolved resolve(List<ProxyHttpRequestResponse> history, BooleanSupplier cancelled) {
        var request = exchange.request();
        var response = exchange.response();
        var timing = exchange.timingData();
        var sent = timing == null ? null : timing.map(SessionAnchor::sentTime).orElse(null);
        ProxyHttpRequestResponse only = null;
        ProxyHttpRequestResponse timed = null;
        ProxyHttpRequestResponse identical = null;
        int matches = 0;
        int timedMatches = 0;
        int identityMatches = 0;
        for (var item : history) {
            if (cancelled.getAsBoolean()) return new Resolved(null, exchange, false);
            var candidate = ProxyMessages.request(item);
            var original = item.request();
            boolean sentRoute = sameRoute(request, candidate);
            boolean originalRoute = original != candidate && sameRoute(request, original);
            if (!sentRoute && !originalRoute) continue;
            var candidateResponse = ProxyMessages.response(item);
            Instant candidateTime = sent == null ? null : sentTime(item.timingData());
            if (sent != null && candidateTime != null && !sent.equals(candidateTime)) continue;
            if ((candidate == request || original == request)
                    && (response == null || response == candidateResponse || response == item.originalResponse())) {
                identical = item;
                identityMatches++;
            }
            if (!(sentRoute && sameRequest(request, candidate) || originalRoute && sameRequest(request, original))
                    || response != null && !sameResponse(response, candidateResponse)
                    && !sameResponse(response, item.originalResponse())) continue;
            only = item;
            matches++;
            if (sent != null && sent.equals(candidateTime)) {
                timed = item;
                timedMatches++;
            }
        }
        if (timedMatches == 1) return complete(timed);
        if (identityMatches == 1) return complete(identical);
        if (matches == 1) return complete(only);
        return new Resolved(null, exchange, matches > 1);
    }

    private Resolved complete(ProxyHttpRequestResponse item) {
        var response = ProxyMessages.response(item);
        return new Resolved(item, HttpRequestResponse.httpRequestResponse(ProxyMessages.request(item),
                response == null ? exchange.response() : response), false);
    }

    private static boolean sameRoute(HttpRequest first, HttpRequest second) {
        if (second == null || !first.method().equals(second.method()) || !first.path().equals(second.path())) {
            return false;
        }
        var firstService = first.httpService();
        var secondService = second.httpService();
        return firstService != null && secondService != null && firstService.port() == secondService.port()
                && firstService.secure() == secondService.secure()
                && firstService.host().equalsIgnoreCase(secondService.host());
    }

    private static boolean sameRequest(HttpRequest first, HttpRequest second) {
        return first == second || Arrays.equals(first.toByteArray().getBytes(), second.toByteArray().getBytes());
    }

    private static boolean sameResponse(HttpResponse first, HttpResponse second) {
        return first == second || second != null && first.statusCode() == second.statusCode()
                && Arrays.equals(first.toByteArray().getBytes(), second.toByteArray().getBytes());
    }

    private static Instant sentTime(TimingData timing) {
        return timing == null || timing.timeRequestSent() == null ? null : timing.timeRequestSent().toInstant();
    }
}
