package trafficworkbench;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Pattern;

final class DiscoveryValues {
    static final Predicate<String> NO_COMPARISON = ignored -> false;
    private static final Pattern LOW_SIGNAL_FIELD = Pattern.compile(
            "(?:^|[^a-z0-9])(?:logs?|logging|telemetry|debug|extra|params?|parameters?|payload|status|metadata)(?=$|[^a-z0-9])");
    private static final Pattern WORD_BREAK = Pattern.compile("([a-z0-9])([A-Z])");
    private static final Pattern UUID = Pattern.compile("[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}");
    private static final Pattern CODE = Pattern.compile("[a-zA-Z0-9_./-]+");
    private static final Pattern LINK_TOKEN = Pattern.compile("_*[\\p{L}\\p{N}][\\p{L}\\p{N}_.@:+$/-]*");
    private static final Pattern LINK_TEXT = Pattern.compile(
            "[\\p{L}\\p{N}][\\p{L}\\p{N}\\p{M}\\p{Zs}.,@:+$/&'_-]*");
    private static final Pattern DATE = Pattern.compile("([0-9]{4}|[0-9]{1,2})([/.-])([0-9]{1,2})\\2([0-9]{4}|[0-9]{1,2})");

    private DiscoveryValues() {}

    static boolean usefulField(FieldExtractor.Pair field) {
        String name = WORD_BREAK.matcher(field.key).replaceAll("$1 $2").toLowerCase(Locale.ROOT);
        return !LOW_SIGNAL_FIELD.matcher(name).find() && !HttpSearchFields.protectedValue(field);
    }

    static boolean linkableValue(String value) {
        return ExtractEngine.isDistinctive(value) && (LINK_TOKEN.matcher(value).matches()
                || value.length() <= 512 && LINK_TEXT.matcher(value).matches() || DateShape.of(value) != null);
    }

    static boolean calendarDate(String value) {
        return DateShape.of(value) != null;
    }

    static Predicate<String> similarTo(String example) {
        if (example == null || !ExtractEngine.isDistinctive(example)) return NO_COMPARISON;
        if (UUID.matcher(example).matches()) return value -> value.length() == 36 && UUID.matcher(value).matches();
        var date = DateShape.of(example);
        if (date != null) return date::matches;
        if (!CODE.matcher(example).matches()) return NO_COMPARISON;
        int digitStart = example.length();
        while (digitStart > 0 && isDigit(example.charAt(digitStart - 1))) digitStart--;
        if (digitStart == example.length()) return NO_COMPARISON;
        int prefixSize = digitStart;
        return value -> {
            if (value.length() != example.length() || !example.regionMatches(true, 0, value, 0, prefixSize)) return false;
            for (int i = prefixSize; i < value.length(); i++) {
                if (!isDigit(value.charAt(i))) return false;
            }
            return true;
        };
    }

    private static boolean isDigit(char value) {
        return value >= '0' && value <= '9';
    }

    private record DateShape(char separator, boolean yearFirst, boolean monthBeforeDay, boolean dayBeforeMonth) {
        static DateShape of(String value) {
            if (value.length() < 8 || value.length() > 10) return null;
            var match = DATE.matcher(value);
            if (!match.matches()) return null;
            boolean yearFirst = match.group(1).length() == 4;
            if (yearFirst == (match.group(4).length() == 4)) return null;
            int first = Integer.parseInt(match.group(1));
            int middle = Integer.parseInt(match.group(3));
            int last = Integer.parseInt(match.group(4));
            char separator = match.group(2).charAt(0);
            if (yearFirst) {
                return valid(first, middle, last) ? new DateShape(separator, true, true, false) : null;
            }
            boolean monthFirst = valid(last, first, middle);
            boolean dayFirst = valid(last, middle, first);
            return monthFirst || dayFirst ? new DateShape(separator, false, monthFirst, dayFirst) : null;
        }

        boolean matches(String value) {
            var other = of(value);
            return other != null && separator == other.separator && yearFirst == other.yearFirst
                    && (monthBeforeDay && other.monthBeforeDay || dayBeforeMonth && other.dayBeforeMonth);
        }

        private static boolean valid(int year, int month, int day) {
            if (year == 0 || month < 1 || month > 12 || day < 1 || day > 31) return false;
            try {
                LocalDate.of(year, month, day);
                return true;
            } catch (DateTimeException ignored) {
                return false;
            }
        }
    }
}
