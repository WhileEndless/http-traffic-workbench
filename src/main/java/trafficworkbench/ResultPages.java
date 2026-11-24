package trafficworkbench;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

final class ResultPages {
    static final int PAGE_SIZE = 200;

    enum Filter {
        ALL("All matches"), DIRECT("Direct matches"), RELATED("Related fields");

        private final String label;

        Filter(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    private final NavigableMap<Integer, List<ResultRow>> byRelevance = new TreeMap<>(Comparator.reverseOrder());
    private final Map<Integer, Integer> positions = new HashMap<>();
    private int direct;
    private int related;

    void add(List<ResultRow> rows) {
        for (var row : rows) {
            var bucket = byRelevance.computeIfAbsent(row.rank(), ignored -> new ArrayList<>());
            var position = positions.putIfAbsent(row.id, bucket.size());
            if (position != null) {
                bucket.set(position, row);
                continue;
            }
            bucket.add(row);
            if (row.related) related++;
            else direct++;
        }
    }

    void clear() {
        byRelevance.clear();
        positions.clear();
        direct = 0;
        related = 0;
    }

    int size(Filter filter) {
        return switch (filter) {
            case ALL -> direct + related;
            case DIRECT -> direct;
            case RELATED -> related;
        };
    }

    List<ResultRow> page(Filter filter, int index) {
        int offset = index * PAGE_SIZE;
        var rows = new ArrayList<ResultRow>(PAGE_SIZE);
        for (var bucket : byRelevance.entrySet()) {
            boolean isRelated = bucket.getKey() < 0;
            if ((filter == Filter.DIRECT && isRelated) || (filter == Filter.RELATED && !isRelated)) continue;
            var matches = bucket.getValue();
            if (offset >= matches.size()) {
                offset -= matches.size();
                continue;
            }
            int end = Math.min(matches.size(), offset + PAGE_SIZE - rows.size());
            rows.addAll(matches.subList(offset, end));
            if (rows.size() == PAGE_SIZE) break;
            offset = 0;
        }
        return rows;
    }
}
