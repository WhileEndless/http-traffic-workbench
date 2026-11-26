package trafficworkbench;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class TrafficWorkbench implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler {
    static final String NAME = "HTTP Traffic Workbench";
    private static final int LIVE_BODY_LIMIT = 256 * 1024;

    private final AtomicBoolean closing = new AtomicBoolean();
    private final AtomicBoolean queueWarning = new AtomicBoolean();
    private final ThreadPoolExecutor capture = new ThreadPoolExecutor(
            1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(256), runnable -> {
                var worker = new Thread(runnable, "http-traffic-workbench-capture");
                worker.setDaemon(true);
                return worker;
            }, (task, executor) -> {
                if (!executor.isShutdown() && queueWarning.compareAndSet(false, true)) {
                    apiWarning();
                }
            });
    private MontoyaApi api;
    private Persistence persistence;
    private CollectorStore store;
    private volatile RuntimeProfile runtime;
    private volatile CollectorTab tab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(NAME);
        persistence = new Persistence(api);
        CaptureProfile profile = persistence.loadProfile();
        runtime = new RuntimeProfile(profile.compile(), new UserLabeler());
        store = new CollectorStore(persistence);
        if (profile.persistArchive()) {
            capture.execute(() -> store.addAll(persistence.loadArchive()));
        }
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.http().registerHttpHandler(new ToolTrafficCapture(() -> runtime.profile, store, capture, this::reportProxyError));
        var menu = new SearchContextMenu(api, store, () -> runtime.profile.settings(), this::saveProfile);
        api.extension().registerUnloadingHandler(() -> {
            closing.set(true);
            menu.close();
            if (tab != null) tab.close();
            capture.shutdown();
            try {
                if (!capture.awaitTermination(3, TimeUnit.SECONDS)) capture.shutdownNow();
            } catch (InterruptedException ex) {
                capture.shutdownNow();
                Thread.currentThread().interrupt();
            }
            store.flushAndShutdown();
        });
        api.userInterface().registerContextMenuItemsProvider(menu);
        SwingUtilities.invokeLater(() -> {
            if (closing.get()) return;
            tab = new CollectorTab(api, store, menu, () -> runtime.profile.settings(), this::saveProfile);
            api.userInterface().registerSuiteTab(NAME, tab.uiComponent());
        });
        api.logging().logToOutput(NAME + " " + BuildInfo.release() + " loaded.");
        api.logging().logToOutput("GitHub repository · " + BuildInfo.REPOSITORY_URL);
        api.logging().logToOutput("GitHub profile · " + BuildInfo.OWNER_URL);
    }

    private void apiWarning() {
        api.logging().logToError(NAME + " · Archive queue is full. Some samples were skipped.");
    }

    private void saveProfile(CaptureProfile profile) throws IOException {
        var compiled = profile.compile();
        if (closing.get()) throw new IOException("The extension is closing.");
        persistence.saveProfile(profile);
        var current = runtime;
        if (!current.profile.settings().equals(profile)) {
            runtime = new RuntimeProfile(compiled, new UserLabeler());
        }
        store.persistSoon();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        var current = runtime;
        var profile = current.profile;
        var settings = profile.settings();
        try {
            if ((settings.annotate() || settings.collect()) && !settings.sessionCookie().isEmpty() && profile.covers(request)) {
                current.requests.sent(request.messageId(), System.currentTimeMillis());
            }
            if (settings.annotate() && settings.sessionCookie().isEmpty()
                    && (settings.source() == CaptureProfile.Source.REQUEST
                        || settings.source() == CaptureProfile.Source.REQUEST_FIRST)
                    && profile.matches(request) && profile.canIdentify(request, LIVE_BODY_LIMIT)) {
                String label = profile.identify(request, request.query(), LIVE_BODY_LIMIT);
                if (!label.isEmpty()) {
                    return ProxyRequestToBeSentAction.continueWith(request,
                            UserLabeler.addNote(request.annotations(), settings, label));
                }
            }
        } catch (RuntimeException ex) {
            reportProxyError(ex);
        }
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        RuntimeProfile current = runtime;
        var profile = current.profile;
        var request = response.initiatingRequest();
        try {
            var settings = profile.settings();
            long received = System.currentTimeMillis();
            Long sent = settings.sessionCookie().isEmpty() ? null : current.requests.completed(response.messageId());
            if ((!settings.collect() && !settings.annotate()) || !profile.covers(request)) {
                return ProxyResponseToBeSentAction.continueWith(response);
            }
            boolean included = profile.includesPath(request);
            if (!included && settings.sessionCookie().isEmpty()) {
                return ProxyResponseToBeSentAction.continueWith(response);
            }
            boolean archive = included && settings.collect()
                    && (!settings.successfulOnly() || response.statusCode() >= 200 && response.statusCode() < 400);
            if (!settings.annotate()) {
                if (archive || !settings.sessionCookie().isEmpty()) {
                    enqueue(current, response, archive, null, sent, received);
                }
                return ProxyResponseToBeSentAction.continueWith(response);
            }
            String label = liveLabel(current, response, LIVE_BODY_LIMIT, sent, received);
            if (archive) {
                enqueue(current, response, true, label, sent, received);
            }
            if (included && !label.isEmpty()) {
                return ProxyResponseToBeSentAction.continueWith(response,
                        UserLabeler.addNote(response.annotations(), settings, label));
            }
        } catch (RuntimeException ex) {
            reportProxyError(ex);
        }
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private String liveLabel(RuntimeProfile current, InterceptedResponse response, int limit, Long sent, long received) {
        // Without a send time, the response can establish its own login but cannot inherit a recorded session.
        long time = sent == null ? Long.MIN_VALUE : sent;
        return current.labeler.label(current.profile, response.initiatingRequest(), response, limit, time,
                Math.max(time, received), true);
    }

    private void enqueue(RuntimeProfile current, InterceptedResponse response, boolean archive, String knownLabel,
                         Long sent, long received) {
        capture.execute(() -> {
            if (runtime != current) return;
            try {
                var request = response.initiatingRequest();
                String label = knownLabel == null ? liveLabel(current, response, Util.MAX_BODY_BYTES, sent, received) : knownLabel;
                if (archive) {
                    var annotations = response.annotations();
                    boolean annotated = current.profile.settings().annotate() && !label.isEmpty()
                            || annotations != null && (annotations.hasNotes() || annotations.hasHighlightColor());
                    store.add(CapturedEntry.of(label, HttpRequestResponse.httpRequestResponse(request, response), received,
                            TrafficSource.ARCHIVE, 0, annotated));
                }
            } catch (RuntimeException ex) {
                reportProxyError(ex);
            }
        });
    }

    private void reportProxyError(RuntimeException error) {
        api.logging().logToError(NAME + " · Could not process an HTTP record (" + error.getClass().getSimpleName() + ").");
    }

    private record RuntimeProfile(CaptureProfile.Compiled profile, UserLabeler labeler, RequestTimes requests) {
        RuntimeProfile(CaptureProfile.Compiled profile, UserLabeler labeler) {
            this(profile, labeler, new RequestTimes());
        }
    }

    private static final class RequestTimes {
        private static final int LIMIT = 4_096;
        private final LinkedHashMap<Integer, Long> sent = new LinkedHashMap<>();

        synchronized void sent(int id, long time) {
            sent.put(id, time);
            if (sent.size() > LIMIT) sent.remove(sent.keySet().iterator().next());
        }

        synchronized Long completed(int id) {
            return sent.remove(id);
        }
    }
}
