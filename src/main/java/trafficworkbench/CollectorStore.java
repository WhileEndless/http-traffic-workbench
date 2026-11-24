package trafficworkbench;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

final class CollectorStore {
    private static final int MAX_PER_ENDPOINT = 10;
    private static final int MAX_ENTRIES = 2_000;
    private static final int MAX_SAMPLE_BYTES = 2 * 1024 * 1024;
    private static final int MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
    private static final long SAVE_SECONDS = 2;

    private final Map<CapturedEntry.Key, List<CapturedEntry>> buckets = new LinkedHashMap<>();
    private final LinkedHashMap<CapturedEntry, Stored> entries = new LinkedHashMap<>();
    private final NavigableSet<Stored> oldestFirst = new TreeSet<>(Comparator
            .comparingLong((Stored item) -> item.entry().time()).thenComparingLong(Stored::sequence));
    private long sequence;
    private final Persistence persistence;
    private final ScheduledExecutorService saver = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "http-traffic-workbench-persistence");
        thread.setDaemon(true);
        return thread;
    });

    private volatile Runnable listener = () -> {};
    private ScheduledFuture<?> pendingSave;
    private int bytes;
    private boolean closed;
    private boolean dirty;

    CollectorStore(Persistence persistence) {
        this.persistence = persistence;
    }

    void setListener(Runnable listener) {
        this.listener = listener;
    }

    void add(CapturedEntry entry) {
        int size = entry.size();
        if (size > MAX_SAMPLE_BYTES) return;
        entry.contentHash();
        synchronized (this) {
            if (!closed && put(entry, size)) changed();
        }
    }

    void addCompleted(CapturedEntry pending, CapturedEntry completed) {
        int size = completed.size();
        if (size > MAX_SAMPLE_BYTES) return;
        completed.contentHash();
        synchronized (this) {
            if (closed) return;
            if (pending != null) pending.attachCompletion(completed);
            boolean removed = pending != null && entries.containsKey(pending);
            if (removed) remove(pending);
            if (put(completed, size) || removed) changed();
        }
    }

    int addAll(List<CapturedEntry> samples) {
        int accepted = 0;
        for (CapturedEntry entry : samples.stream().sorted(Comparator.comparingLong(CapturedEntry::time)).toList()) {
            if (Thread.currentThread().isInterrupted()) break;
            int size = entry.size();
            if (size > MAX_SAMPLE_BYTES) continue;
            entry.contentHash();
            synchronized (this) {
                if (closed) break;
                if (put(entry, size)) accepted++;
            }
        }
        synchronized (this) {
            if (accepted > 0 && !closed) changed();
        }
        return accepted;
    }

    private boolean put(CapturedEntry entry, int size) {
        var key = entry.key();
        var bucket = buckets.computeIfAbsent(key, ignored -> new ArrayList<>());
        CapturedEntry duplicate = bucket.stream().filter(entry::matches).findFirst().orElse(null);
        if (duplicate != null) {
            if (entry.time() <= duplicate.time()) {
                return false;
            }
            remove(duplicate);
        } else if (bucket.size() >= MAX_PER_ENDPOINT) {
            CapturedEntry oldest = bucket.stream().min(Comparator.comparingLong(CapturedEntry::time)).orElseThrow();
            if (entry.time() < oldest.time()) {
                return false;
            }
            remove(oldest);
        }
        buckets.computeIfAbsent(key, ignored -> new ArrayList<>()).add(entry);
        var stored = new Stored(entry, size, sequence++);
        entries.put(entry, stored);
        oldestFirst.add(stored);
        bytes += size;
        while (entries.size() > MAX_ENTRIES || bytes > MAX_ARCHIVE_BYTES) {
            remove(oldestFirst.first().entry());
        }
        return entries.containsKey(entry);
    }

    private void remove(CapturedEntry entry) {
        var stored = entries.remove(entry);
        oldestFirst.remove(stored);
        bytes -= stored.size();
        var key = entry.key();
        var bucket = buckets.get(key);
        bucket.remove(entry);
        if (bucket.isEmpty()) {
            buckets.remove(key);
        }
    }

    synchronized List<CapturedEntry> all() {
        return List.copyOf(entries.keySet());
    }

    synchronized void clear() {
        entries.clear();
        buckets.clear();
        oldestFirst.clear();
        bytes = 0;
        changed();
    }

    private void changed() {
        persistSoon();
        listener.run();
    }

    synchronized void persistSoon() {
        if (closed || !persistence.archiveEnabled()) return;
        dirty = true;
        scheduleSave();
    }

    private void scheduleSave() {
        if (pendingSave == null || pendingSave.isDone()) {
            pendingSave = saver.schedule(this::saveSnapshot, SAVE_SECONDS, TimeUnit.SECONDS);
        }
    }

    private void saveSnapshot() {
        List<CapturedEntry> snapshot;
        synchronized (this) {
            pendingSave = null;
            if (!dirty || !persistence.archiveEnabled()) return;
            dirty = false;
            snapshot = all();
        }
        if (!persistence.saveArchive(snapshot)) {
            synchronized (this) {
                // A later change or unload can retry without continuously writing a failing store.
                dirty = true;
            }
        }
    }

    private record Stored(CapturedEntry entry, int size, long sequence) {}

    void flushAndShutdown() {
        synchronized (this) {
            closed = true;
            if (pendingSave != null) {
                pendingSave.cancel(false);
            }
        }
        // The final write follows any in-progress snapshot on the same executor.
        var flush = saver.submit(this::saveSnapshot);
        saver.shutdown();
        try {
            flush.get();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (java.util.concurrent.ExecutionException ex) {
            throw new IllegalStateException(ex.getCause());
        }
    }
}
