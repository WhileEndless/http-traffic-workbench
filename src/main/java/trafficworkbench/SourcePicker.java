package trafficworkbench;

import javax.swing.*;
import java.awt.*;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

final class SourcePicker extends JButton {
    private final Map<TrafficSource, JCheckBox> choices = new EnumMap<>(TrafficSource.class);
    private final JPopupMenu popup = new JPopupMenu();
    private final String title;

    SourcePicker(String title, Set<TrafficSource> allowed, Set<TrafficSource> selected) {
        this.title = title;
        var panel = new JPanel();
        panel.setBorder(BorderFactory.createEmptyBorder(8, 9, 8, 9));
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        var controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        var all = new JButton("All");
        var none = new JButton("None");
        all.addActionListener(event -> select(allowed));
        none.addActionListener(event -> select(Set.of()));
        controls.add(all);
        controls.add(none);
        controls.setAlignmentX(LEFT_ALIGNMENT);
        panel.add(controls);
        panel.add(Box.createVerticalStrut(4));

        if (allowed.stream().anyMatch(source -> !source.toolTraffic())) {
            addGroup(panel, "Burp project and extension data", allowed, false);
        }
        if (allowed.stream().anyMatch(TrafficSource::toolTraffic)) {
            addGroup(panel, "Captured or imported tool traffic", allowed, true);
        }
        popup.add(panel);
        setComponentPopupMenu(popup);
        addActionListener(event -> popup.show(this, 0, getHeight()));
        select(selected);
    }

    private void addGroup(JPanel panel, String title, Set<TrafficSource> allowed, boolean tools) {
        int columns = allowed.size() > 5 ? 2 : 1;
        var group = new JPanel(new GridLayout(0, columns, 12, 3));
        group.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(3, 7, 5, 7)));
        group.setAlignmentX(LEFT_ALIGNMENT);
        for (TrafficSource source : TrafficSource.values()) {
            if (!allowed.contains(source) || source.toolTraffic() != tools) continue;
            var choice = new JCheckBox(source.label);
            if (source == TrafficSource.ARCHIVE) {
                choice.setToolTipText("Proxy samples and imports held by HTTP Traffic Workbench.");
            }
            choice.addActionListener(event -> refresh());
            choices.put(source, choice);
            group.add(choice);
        }
        panel.add(group);
    }

    void whenClosed(Runnable action) {
        popup.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent event) { }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent event) { action.run(); }
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent event) { }
        });
    }

    Set<TrafficSource> selected() {
        var result = EnumSet.noneOf(TrafficSource.class);
        choices.forEach((source, button) -> {
            if (button.isSelected()) result.add(source);
        });
        return result;
    }

    void select(Set<TrafficSource> sources) {
        choices.forEach((source, button) -> button.setSelected(sources.contains(source)));
        refresh();
    }

    private void refresh() {
        var selected = selected();
        setText(title + " (" + selected.size() + ") ▾");
        setToolTipText(selected.isEmpty() ? "No sources selected"
                : String.join(", ", selected.stream().map(TrafficSource::toString).toList()));
    }
}
