package trafficworkbench;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.IntConsumer;

final class HistoryLabeler {
    private static final int MAX_CHANGES = 25_000;

    record Change(Annotations annotations, String label) {}
    record Example(String url, String label) {}
    record Plan(String prefix, List<Change> changes, List<Example> sample, int scanned, int existing,
                int distinctUsers, boolean limited) {}

    private HistoryLabeler() {}

    static Plan plan(List<ProxyHttpRequestResponse> history, CaptureProfile.Compiled profile,
                     BooleanSupplier cancelled, IntConsumer progress) {
        return plan(history, profile, null, cancelled, progress);
    }

    static Plan plan(List<ProxyHttpRequestResponse> history, CaptureProfile.Compiled profile,
                     ProxyHttpRequestResponse anchor, BooleanSupplier cancelled, IntConsumer progress) {
        var filtered = new ArrayList<TimedEntry>();
        for (var record : history) {
            if (cancelled.getAsBoolean()) break;
            HttpRequest request = ProxyMessages.request(record);
            if (request != null && profile.covers(request)) {
                var timestamp = record.time();
                long time = timestamp == null ? 0 : timestamp.toInstant().toEpochMilli();
                filtered.add(new TimedEntry(record, request, time));
            }
        }
        filtered.sort(Comparator.comparingLong(TimedEntry::time));
        var labeler = new UserLabeler();
        var changes = new ArrayList<Change>();
        var users = new java.util.HashSet<String>();
        var sample = new ArrayList<Example>(50);
        String prefix = profile.settings().notePrefix();
        int scanned = 0;
        int existing = 0;
        boolean limited = false;
        boolean reachedAnchor = anchor == null;
        for (TimedEntry entry : filtered) {
            if (cancelled.getAsBoolean()) break;
            var record = entry.record();
            if (record == anchor) reachedAnchor = true;
            if (!reachedAnchor) continue;
            // Yield between batches so a large history does not occupy a core continuously.
            if ((scanned++ & 31) == 0) {
                progress.accept((int) (100L * scanned / filtered.size()));
                java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
            }
            String label = labeler.label(profile, entry.request(), ProxyMessages.response(record),
                    Util.MAX_BODY_BYTES, entry.time(), anchor == null || record == anchor);
            if (label.isEmpty() || !profile.includesPath(entry.request())) continue;
            var annotations = record.annotations();
            if (annotations == null) continue;
            users.add(label);
            if (hasLabel(annotations.notes(), prefix)) {
                existing++;
            } else if (changes.size() < MAX_CHANGES) {
                changes.add(new Change(annotations, label));
                if (sample.size() < 50) sample.add(new Example(entry.request().url(), label));
            } else {
                limited = true;
            }
        }
        return new Plan(prefix, List.copyOf(changes), List.copyOf(sample), scanned, existing, users.size(), limited);
    }

    static int apply(Plan plan, BooleanSupplier cancelled, IntConsumer progress) {
        int applied = 0;
        int i = 0;
        for (Change change : plan.changes()) {
            if (cancelled.getAsBoolean()) break;
            if ((i++ & 31) == 0) {
                progress.accept((int) (100L * i / plan.changes().size()));
                java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
            }
            Annotations annotations = change.annotations();
            String notes = annotations.notes();
            if (!hasLabel(notes, plan.prefix())) {
                annotations.setNotes(UserLabeler.noteText(notes, plan.prefix(), change.label()));
                applied++;
            }
        }
        return applied;
    }

    private static boolean hasLabel(String notes, String prefix) {
        return notes != null && notes.lines().anyMatch(line -> line.startsWith(prefix + ": "));
    }

    private record TimedEntry(ProxyHttpRequestResponse record, HttpRequest request, long time) {}
}
