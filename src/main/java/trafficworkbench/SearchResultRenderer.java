package trafficworkbench;

import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

final class SearchResultRenderer extends DefaultTableCellRenderer {
    private static final Color[] LIGHT = {
            new Color(0x17643A), new Color(0x46651F), new Color(0x8B4B0A), new Color(0x526170)
    };
    private static final Color[] DARK = {
            new Color(0x80E3A2), new Color(0xC1DE89), new Color(0xFFC587), new Color(0xB6C4D2)
    };

    private final boolean relevance;

    SearchResultRenderer(boolean relevance) {
        this.relevance = relevance;
        putClientProperty("html.disable", Boolean.TRUE);
        setHorizontalAlignment(relevance ? SwingConstants.RIGHT : SwingConstants.LEADING);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                    boolean focused, int row, int column) {
        super.getTableCellRendererComponent(table, value, selected, focused, row, column);
        if (relevance) setFont(table.getFont().deriveFont(Font.BOLD));
        if (!selected) {
            Color base = table.getBackground();
            Color text = table.getForeground();
            Color fill = (row & 1) == 0 ? base : stripe(base, text);
            setBackground(fill);
            setForeground(relevance && value instanceof Number score
                    ? scoreColor(score.intValue(), fill, text) : text);
        }
        return this;
    }

    private static Color scoreColor(int score, Color background, Color fallback) {
        int tier = score >= 100 ? 0 : score >= 80 ? 1 : score >= 60 ? 2 : 3;
        Color accent = (luminance(background) < 0.18 ? DARK : LIGHT)[tier];
        double first = luminance(accent);
        double second = luminance(background);
        double contrast = (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
        return contrast >= 4.5 ? accent : fallback;
    }

    private static double luminance(Color color) {
        return .2126 * linear(color.getRed()) + .7152 * linear(color.getGreen()) + .0722 * linear(color.getBlue());
    }

    private static double linear(int channel) {
        double normalized = channel / 255.0;
        return normalized <= .04045 ? normalized / 12.92 : Math.pow((normalized + .055) / 1.055, 2.4);
    }

    private static Color stripe(Color base, Color text) {
        return new Color((base.getRed() * 24 + text.getRed()) / 25,
                (base.getGreen() * 24 + text.getGreen()) / 25,
                (base.getBlue() * 24 + text.getBlue()) / 25);
    }
}
