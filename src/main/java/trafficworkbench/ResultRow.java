package trafficworkbench;

/** A single result with its source message and matching reason. */
final class ResultRow {
    final int id;
    final int relevance;
    final String userCode;
    final String endpoint;
    final String source;
    final String key;
    final String value;
    final String reason;
    final CapturedEntry entry;
    final boolean related;
    final String editorSearch;

    ResultRow(int id, int relevance, String userCode, String endpoint, String source, String key,
              String value, String reason, CapturedEntry entry, boolean related, String editorSearch) {
        this.id = id;
        this.relevance = relevance;
        this.userCode = userCode;
        this.endpoint = endpoint;
        this.source = source;
        this.key = key;
        this.value = value;
        this.reason = reason;
        this.entry = entry;
        this.related = related;
        this.editorSearch = editorSearch;
    }

    ResultRow withExchange(CapturedEntry completed, String value, String editorSearch) {
        return new ResultRow(id, relevance, userCode, completed.requestResponse().request().url(), source, key,
                value, reason, completed, related, editorSearch);
    }

    int rank() {
        return related ? relevance - 100 : relevance;
    }
}
