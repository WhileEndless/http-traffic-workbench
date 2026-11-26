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
        return label(profile, request, response, limit, time, time, allowNewSession);
    }

    String label(CaptureProfile.Compiled profile, HttpRequest request, HttpResponse response,
                 int limit, long time, long responseTime, boolean allowNewSession) {
        if (profile.settings().expression().isEmpty()) {
            return "";
        }
        Supplier<String> fromRequest = () -> profile.identify(request, request.query(), limit);
        Supplier<String> fromResponse = () -> profile.identify(response, null, limit);
        boolean logout = profile.logout().matchesRequest(request, limit);
        boolean start = !logout && profile.canIdentify(request, limit);
        boolean newLogin = start && profile.hasExplicitStart();
        boolean confirmedLogin = profile.settings().sessionCookie().isEmpty()
                || response != null && response.statusCode() >= 200 && response.statusCode() < 400;
        String direct = !start || !allowNewSession || !confirmedLogin ? "" : switch (profile.settings().source()) {
            case REQUEST -> fromRequest.get();
            case RESPONSE -> fromResponse.get();
            case REQUEST_FIRST -> first(fromRequest, fromResponse);
            case RESPONSE_FIRST -> first(fromResponse, fromRequest);
        };
        if (profile.settings().sessionCookie().isEmpty()) {
            return direct;
        }
        return correlate(profile, request, response, direct, time, responseTime, newLogin,
                logout && profile.logout().confirms(response, limit));
    }

    synchronized boolean hasSession() {
        return !sessions.isEmpty();
    }

    private synchronized String correlate(CaptureProfile.Compiled profile, HttpRequest request,
                                          HttpResponse response, String direct, long now, long responseTime, boolean newLogin,
                                          boolean loggedOut) {
        String name = profile.settings().sessionCookie();
        var incoming = Cookies.fields(request, false, name).stream()
                .map(Cookies.Field::value).filter(value -> !value.isEmpty()).distinct().toList();
        var updates = Cookies.fields(response, true, name).stream().distinct().toList();
        if (incoming.size() > 1 || updates.size() > 1) {
            if (newLogin || loggedOut || !updates.isEmpty()) {
                incoming.forEach(value -> sessions.remove(sessionKey(request, value)));
                updates.forEach(update -> sessions.remove(sessionKey(request, update.value())));
            }
            return direct;
        }
        SessionKey key = sessionKey(request, incoming.isEmpty() ? "" : incoming.get(0));
        Session existing = key == null ? null : sessions.get(key);
        var update = updates.isEmpty() ? null : updates.get(0);
        SessionKey newKey = update == null ? null : sessionKey(request, update.value());
        Session destination = newKey == null || newKey.equals(key) ? null : sessions.get(newKey);
        if (existing != null && now < existing.availableAt || destination != null && now < destination.availableAt) {
            // Overlapping transitions can disagree about who owns a cookie. Wait for a later login to re-establish it.
            if (newLogin || loggedOut || update != null) {
                sessions.remove(key);
                sessions.remove(newKey);
            }
            return direct;
        }
        long ttl = profile.settings().sessionMinutes() * 60_000L;
        if (existing != null && expired(existing, now, ttl)) {
            sessions.remove(key);
            existing = null;
        }
        String previous = existing == null || newLogin ? "" : existing.user;
        String label = direct.isEmpty() ? previous : direct;
        boolean conflictingRotation = !newLogin && !label.isEmpty() && destination != null
                && !expired(destination, now, ttl) && !destination.user.equals(label);
        if (loggedOut || conflictingRotation || update != null && update.expiredAt(responseTime) || newLogin && direct.isEmpty()) {
            sessions.remove(key);
            sessions.remove(newKey);
        } else if (update != null && label.isEmpty()) {
            // A response without a known session can reissue a previously observed cookie.
            sessions.remove(newKey);
        } else if (!label.isEmpty()) {
            if (key != null && newKey != null && !newKey.equals(key)) {
                sessions.remove(key);
            }
            SessionKey current = newKey == null ? key : newKey;
            if (current != null) {
                long expiry = update != null ? update.expiryAt(responseTime) : existing == null ? Long.MAX_VALUE : existing.expiresAt;
                long available = !direct.isEmpty() || update != null ? responseTime : existing.availableAt;
                long lastSeen = existing == null ? Math.max(now, available) : Math.max(existing.lastSeen, Math.max(now, available));
                sessions.put(current, new Session(label, lastSeen, expiry, available));
                if (sessions.size() > MAX_SESSIONS) {
                    sessions.remove(sessions.keySet().iterator().next());
                }
            }
        }
        return label;
    }

    private static boolean expired(Session session, long now, long idleTimeout) {
        return now >= session.expiresAt || idleTimeout > 0 && now - session.lastSeen > idleTimeout;
    }

    private static String first(Supplier<String> primary, Supplier<String> fallback) {
        String result = primary.get();
        return result.isEmpty() ? fallback.get() : result;
    }

    private static SessionKey sessionKey(HttpRequest request, String cookie) {
        var service = request.httpService();
        return cookie.isEmpty() ? null : new SessionKey(service.host().toLowerCase(java.util.Locale.ROOT), service.port(), service.secure(), cookie);
    }

    static Annotations addNote(Annotations annotations, CaptureProfile profile, String label) {
        String current = annotations.notes();
        if (!readNote(current, profile).isEmpty()) return annotations;
        return annotations.withNotes(noteText(current, profile.notePrefix(), label));
    }

    static String noteText(String notes, String prefix, String label) {
        String line = prefix + ": " + label;
        if (notes == null || notes.isBlank()) {
            return line;
        }
        return notes.lines().anyMatch(line::equals) ? notes : notes + "\n" + line;
    }

    static String readNote(String notes, CaptureProfile profile) {
        if (notes == null || notes.isBlank()) return "";
        String prefix = profile.notePrefix();
        String selectedField = switch (profile.locator()) {
            case FIELD, HEADER -> profile.expression();
            case REGEX -> "";
        };
        String configuredLabel = "";
        String selectedFieldLabel = "";
        String alternateLabel = "";
        var lines = notes.lines().iterator();
        while (lines.hasNext()) {
            String line = lines.next().stripLeading();
            String value = noteValue(line, prefix);
            if (!value.isEmpty()) configuredLabel = value;
            value = profile.locator() == CaptureProfile.Locator.FIELD && !line.startsWith(selectedField)
                    ? "" : noteValue(line, selectedField);
            if (!value.isEmpty()) selectedFieldLabel = value;
            if (prefix.equalsIgnoreCase("User")) {
                value = noteValue(line, "User Code");
                if (value.isEmpty()) value = noteValue(line, "UserCode");
                if (!value.isEmpty()) alternateLabel = value;
            }
        }
        if (!configuredLabel.isEmpty()) return configuredLabel;
        return selectedFieldLabel.isEmpty() ? alternateLabel : selectedFieldLabel;
    }

    private static String noteValue(String line, String name) {
        if (name.isEmpty() || !line.regionMatches(true, 0, name, 0, name.length())) return "";
        String rest = line.substring(name.length()).stripLeading();
        return rest.startsWith(":") ? rest.substring(1).strip() : "";
    }

    private record SessionKey(String host, int port, boolean secure, String cookie) {}
    private record Session(String user, long lastSeen, long expiresAt, long availableAt) {}

}
