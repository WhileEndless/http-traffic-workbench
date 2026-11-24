package trafficworkbench;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

final class ProxyMessages {
    private ProxyMessages() {}

    static HttpRequest request(ProxyHttpRequestResponse item) {
        var sent = item.finalRequest();
        return sent == null ? item.request() : sent;
    }

    static HttpResponse response(ProxyHttpRequestResponse item) {
        var response = item.response();
        return response == null ? item.originalResponse() : response;
    }
}
