package trafficworkbench;

import java.time.Duration;
import java.util.regex.Pattern;

final class TimedRegex {
    private static final long BUDGET = Duration.ofMillis(20).toNanos();
    private static final int MAX_EXPRESSION = 512;

    private TimedRegex() {}

    static Pattern compile(String expression) {
        return compile(expression, 0);
    }

    static Pattern compile(String expression, int flags) {
        if (expression.length() > MAX_EXPRESSION) {
            throw new IllegalArgumentException("Regex can be up to " + MAX_EXPRESSION + " characters long.");
        }
        return Pattern.compile(expression, flags);
    }

    static boolean finds(Pattern pattern, String value) {
        try {
            return pattern.matcher(new Input(value)).find();
        } catch (TimeLimit | StackOverflowError ignored) {
            return false;
        }
    }

    record Span(int start, int end, boolean limited) {
        boolean found() { return start >= 0; }
    }

    static Span locate(Pattern pattern, String value, boolean timed) {
        try {
            var matcher = pattern.matcher(timed ? new Input(value) : value);
            return matcher.find() ? new Span(matcher.start(), matcher.end(), false) : new Span(-1, -1, false);
        } catch (TimeLimit | StackOverflowError ignored) {
            return new Span(-1, -1, true);
        }
    }

    static String group(Pattern pattern, String value) {
        try {
            var matcher = pattern.matcher(new Input(value));
            return matcher.find() ? matcher.group(1) : null;
        } catch (TimeLimit | StackOverflowError ignored) {
            return null;
        }
    }

    private static final class Input implements CharSequence {
        private final String value;
        private final long start = System.nanoTime();

        Input(String value) { this.value = value; }
        @Override public int length() { return value.length(); }
        @Override public char charAt(int index) {
            if (System.nanoTime() - start > BUDGET || Thread.currentThread().isInterrupted()) {
                throw new TimeLimit();
            }
            return value.charAt(index);
        }
        @Override public CharSequence subSequence(int start, int end) { return value.subSequence(start, end); }
        @Override public String toString() { return value; }
    }

    private static final class TimeLimit extends RuntimeException {
        TimeLimit() { super(null, null, false, false); }
    }
}
