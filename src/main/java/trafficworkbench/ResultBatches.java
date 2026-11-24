package trafficworkbench;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

final class ResultBatches {
    private static final int BATCH_SIZE = 96;
    private static final long INTERVAL_NANOS = 40_000_000;

    private final Consumer<List<ResultRow>> publish;
    private final List<ResultRow> pending = new ArrayList<>(BATCH_SIZE);
    private long lastPublish;

    ResultBatches(Consumer<List<ResultRow>> publish) {
        this.publish = publish;
    }

    void add(ResultRow row) {
        pending.add(row);
        if (lastPublish == 0 || pending.size() >= BATCH_SIZE) flush();
        else flushIfDue();
    }

    void flushIfDue() {
        if (!pending.isEmpty() && System.nanoTime() - lastPublish >= INTERVAL_NANOS) flush();
    }

    void flush() {
        if (pending.isEmpty()) return;
        publish.accept(List.copyOf(pending));
        pending.clear();
        lastPublish = System.nanoTime();
    }
}
