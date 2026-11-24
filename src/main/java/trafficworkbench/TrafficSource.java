package trafficworkbench;

import burp.api.montoya.core.ToolType;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

enum TrafficSource {
    PROXY("Proxy history"),
    SITE_MAP("Target site map"),
    FINDINGS("Scanner findings"),
    ORGANIZER("Organizer"),
    ARCHIVE("Extension archive"),
    SCANNER("Scanner"),
    REPEATER("Repeater"),
    INTRUDER("Intruder"),
    EXTENSIONS("Extensions"),
    SEQUENCER("Sequencer"),
    SESSION("Session handling and replay"),
    BURP_AI("Burp AI"),
    OTHER("Other Burp tools");

    final String label;

    TrafficSource(String label) {
        this.label = label;
    }

    boolean toolTraffic() {
        return ordinal() >= SCANNER.ordinal();
    }

    static Set<TrafficSource> capturedSources() {
        return EnumSet.range(SCANNER, OTHER);
    }

    static TrafficSource forTool(ToolType tool) {
        return fromToolName(tool == null ? "" : tool.name());
    }

    static TrafficSource fromToolName(String tool) {
        return switch (tool.strip().toUpperCase(Locale.ROOT).replace(' ', '_').replace('-', '_')) {
            case "PROXY" -> ARCHIVE;
            case "SCANNER" -> SCANNER;
            case "REPEATER" -> REPEATER;
            case "INTRUDER" -> INTRUDER;
            case "EXTENDER", "EXTENSION", "EXTENSIONS" -> EXTENSIONS;
            case "SEQUENCER" -> SEQUENCER;
            case "SESSION_HANDLING", "RECORDED_LOGIN_REPLAYER", "RECORDED_LOGIN_REPLAY", "LOGIN_REPLAYER" -> SESSION;
            case "BURP_AI" -> BURP_AI;
            case "ORGANIZER" -> ORGANIZER;
            case "TARGET" -> SITE_MAP;
            case "" -> ARCHIVE;
            default -> OTHER;
        };
    }

    @Override public String toString() {
        return label;
    }
}
