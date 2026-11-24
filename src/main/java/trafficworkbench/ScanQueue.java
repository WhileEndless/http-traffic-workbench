package trafficworkbench;

import javax.swing.SwingWorker;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

final class ScanQueue implements AutoCloseable {
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(4), task -> {
                var thread = new Thread(task, "http-traffic-workbench-scan");
                thread.setDaemon(true);
                thread.setPriority(Thread.MIN_PRIORITY);
                return thread;
            });

    boolean submit(SwingWorker<?, ?> worker) {
        try {
            executor.execute(worker);
            return true;
        } catch (RejectedExecutionException ignored) {
            return false;
        }
    }

    void cancel(SwingWorker<?, ?> worker) {
        worker.cancel(true);
        executor.remove(worker);
    }

    @Override public void close() {
        executor.shutdownNow().forEach(task -> ((SwingWorker<?, ?>) task).cancel(false));
    }
}
