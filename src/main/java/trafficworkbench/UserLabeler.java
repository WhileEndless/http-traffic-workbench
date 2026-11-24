package trafficworkbench;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

final class UserLabeler {
    private static final int MAX_SESSIONS = 2_000;
    private final Map<SessionKey, Session> sessions = new LinkedHashMap<>(16, 0.75f, true);

    String label(CaptureProfile.Compiled profile, HttpRequest request, HttpResponse response, int limit) {
        return label(profile, request, response, limit, System.currentTimeMillis());
    }

    String label(CaptureProfile.Compiled profile, HttpRequest request, HttpResponse response, int limit, long time) {
        return label(profile, request, response, limit, time, true);
    }

    String label(CaptureProfile.Compiled profile, HttpRequest request, HttpResponse response,
                 int limit, long time, boolean allowNewSession) {
        if (profile.settings().expression().isEmpty()) {
            return "";
        }
        Supplier<String> fromRequest = () -> profile.identify(request, request.query(), limit);
        Supplier<String> fromResponse = () -> profile.identify(response, null, limit);
        boolean logout = profile.logout().matchesRequest(request, limit);
        boolean start = !logout && profile.canIdentify(request, limit);
        String direct = !start || !allowNewSession ? "" : switch (profile.settings().source()) {
            case REQUEST -> fromRequest.get();
            case RESPONSE -> fromResponse.get();
            case REQUEST_FIRST -> first(fromRequest, fromResponse);
            case RESPONSE_FIRST -> first(fromResponse, fromRequest);
        };
        if (profile.settings().sessionCookie().isEmpty()) {
            return direct;
        }
        return correlate(profile, request, response, direct, time, start && profile.hasExplicitStart(),
                logout && profile.logout().confirms(response, limit));
    }

    private synchronized String correlate(CaptureProfile.Compiled profile, HttpRequest request,
                                          HttpResponse response, String direct, long now, boolean newLogin,
                                          boolean loggedOut) {
        String name = profile.settings().sessionCookie();
        var incoming = Cookies.fields(request, false, name).stream()
                .map(Cookies.Field::value).filter(value -> !value.isEmpty()).distinct().limit(2).toList();
        if (incoming.size() > 1) return direct;
        SessionKey key = sessionKey(request, incoming.isEmpty() ? "" : incoming.get(0));
        Session existing = key == null ? null : sessions.get(key);
        long ttl = profile.settings().sessionMinutes() * 60_000L;
        boolean expired = existing != null && ttl > 0 && now - existing.lastSeen > ttl;
        String previous = existing == null || expired || newLogin ? "" : existing.user;
        String label = direct.isEmpty() ? previous : direct;
        if (loggedOut) {
            sessions.remove(key);
            return label;
        }
        var updates = Cookies.fields(response, true, name).stream()
                .distinct().limit(2).toList();
        if (updates.size() > 1) {
            sessions.remove(key);
            return direct;
        }
        var update = updates.isEmpty() ? null : updates.get(0);
        SessionKey newKey = update == null ? null : sessionKey(request, update.value());
        if (update != null && update.expiredAt(now) || newLogin && direct.isEmpty()) {
            sessions.remove(key);
            sessions.remove(newKey);
        } else if (!label.isEmpty()) {
            if (key != null && newKey != null && !newKey.equals(key)) {
                sessions.remove(key);
            }
            SessionKey current = newKey == null ? key : newKey;
            if (current != null) {
                sessions.put(current, new Session(label, now));
                if (sessions.size() > MAX_SESSIONS) {
                    sessions.remove(sessions.keySet().iterator().next());
                }
            }
        }
        return label;
    }

    private static String first(Supplier<String> primary, Supplier<String> fallback) {
        String result = primary.get();
        return result.isEmpty() ? fallback.get() : result;
    }

    private static SessionKey sessionKey(HttpRequest request, String cookie) {
        var service = request.httpService();
        return cookie.isEmpty() ? null : new SessionKey(service.host().toLowerCase(java.util.Locale.ROOT), service.port(), service.secure(), cookie);
    }

    static Annotations addNote(Annotations annotations, String prefix, String label) {
        String current = annotations.notes();
        String updated = noteText(current, prefix, label);
        return updated.equals(current) ? annotations : annotations.withNotes(updated);
    }

    static String noteText(String notes, String prefix, String label) {
        String line = prefix + ": " + label;
        if (notes == null || notes.isBlank()) {
            return line;
        }
        return notes.lines().anyMatch(line::equals) ? notes : notes + "\n" + line;
    }

    private record SessionKey(String host, int port, boolean secure, String cookie) {}
    private record Session(String user, long lastSeen) {}

}
