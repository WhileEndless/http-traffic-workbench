package trafficworkbench;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.IntConsumer;

final class HistoryLabeler {
    private static final int MAX_CHANGES = 25_000;

    record Change(Annotations annotations, String label) {}
    record Example(String url, String label) {}
    record Plan(CaptureProfile profile, List<Change> changes, List<Example> sample, int scanned, int existing,
                int conflicts, int undated, int distinctUsers, boolean limited) {}
    record ApplyResult(int added, int existing, int conflicts, int failed) {}

    private HistoryLabeler() {}

    static Plan plan(List<ProxyHttpRequestResponse> history, CaptureProfile.Compiled profile,
                     BooleanSupplier cancelled, IntConsumer progress) {
        return plan(history, profile, null, cancelled, progress);
    }

    static Plan plan(List<ProxyHttpRequestResponse> history, CaptureProfile.Compiled profile,
                     ProxyHttpRequestResponse anchor, BooleanSupplier cancelled, IntConsumer progress) {
        var filtered = new ArrayList<TimedEntry>();
        int undated = 0;
        for (var record : history) {
            if (cancelled.getAsBoolean()) break;
            HttpRequest request = ProxyMessages.request(record);
            if (request != null && profile.covers(request)) {
                var timing = record.timingData();
                var sent = timing == null ? null : timing.timeRequestSent();
                if (sent == null) sent = record.time();
                var time = sent == null ? null : sent.toInstant();
                if (time == null) {
                    if (record == anchor) throw new IllegalArgumentException("The selected login has no timestamp.");
                    undated++;
                } else {
                    var duration = timing == null ? null : timing.timeBetweenRequestSentAndEndOfResponse();
                    if (timing != null && duration == null) duration = timing.timeBetweenRequestSentAndStartOfResponse();
                    var completed = duration == null || duration.isNegative() ? time : time.plus(duration);
                    long responseTime = completed.toEpochMilli();
                    // Round up so an earlier request in the same millisecond cannot inherit a future response.
                    if (completed.getNano() % 1_000_000 != 0) responseTime++;
                    filtered.add(new TimedEntry(record, request, time, responseTime));
                }
            }
        }
        filtered.sort(Comparator.comparing(TimedEntry::time));
        var labeler = new UserLabeler();
        var changes = new ArrayList<Change>();
        var users = new java.util.HashSet<String>();
        var sample = new ArrayList<Example>(50);
        int scanned = 0;
        int existing = 0;
        int conflicts = 0;
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
                    Util.MAX_BODY_BYTES, entry.time().toEpochMilli(), entry.responseTime(), anchor == null || record == anchor);
            if (record == anchor && !labeler.hasSession()) {
                throw new IllegalArgumentException("The selected login could not establish a session. Check the response status, identifier and cookie.");
            }
            if (label.isEmpty() || !profile.includesPath(entry.request())) continue;
            var annotations = record.annotations();
            if (annotations == null) continue;
            users.add(label);
            String current = UserLabeler.readNote(annotations.notes(), profile.settings());
            if (!current.isEmpty()) {
                existing++;
                if (!current.equals(label)) conflicts++;
            } else if (changes.size() < MAX_CHANGES) {
                changes.add(new Change(annotations, label));
                if (sample.size() < 50) sample.add(new Example(entry.request().url(), label));
            } else {
                limited = true;
            }
        }
        if (!cancelled.getAsBoolean()) progress.accept(100);
        return new Plan(profile.settings(), List.copyOf(changes), List.copyOf(sample), scanned, existing, conflicts,
                undated, users.size(), limited);
    }

    static ApplyResult apply(Plan plan, BooleanSupplier cancelled, IntConsumer progress) {
        int applied = 0;
        int existing = 0;
        int conflicts = 0;
        int failed = 0;
        int i = 0;
        for (Change change : plan.changes()) {
            if (cancelled.getAsBoolean()) break;
            if ((i++ & 31) == 0) {
                progress.accept((int) (100L * i / plan.changes().size()));
                java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
            }
            try {
                Annotations annotations = change.annotations();
                String notes = annotations.notes();
                String current = UserLabeler.readNote(notes, plan.profile());
                if (current.isEmpty()) {
                    annotations.setNotes(UserLabeler.noteText(notes, plan.profile().notePrefix(), change.label()));
                    applied++;
                } else {
                    existing++;
                    if (!current.equals(change.label())) conflicts++;
                }
            } catch (RuntimeException ex) {
                failed++;
            }
        }
        if (!cancelled.getAsBoolean()) progress.accept(100);
        return new ApplyResult(applied, existing, conflicts, failed);
    }

    private record TimedEntry(ProxyHttpRequestResponse record, HttpRequest request, Instant time, long responseTime) {}
}
