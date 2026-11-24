package trafficworkbench;

import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Locale;

final class Dialogs {
    private Dialogs() {}

    static JPanel heading(String title, String detail) {
        var heading = new JPanel(new BorderLayout(0, 5));
        var label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize2D() + 5));
        heading.add(label, BorderLayout.NORTH);
        if (!detail.isBlank()) heading.add(new JLabel(detail), BorderLayout.CENTER);
        return heading;
    }

    static JPanel stack(int gap, JComponent... children) {
        var panel = new JPanel(new GridBagLayout());
        var position = new GridBagConstraints();
        position.gridx = 0;
        position.gridy = 0;
        position.weightx = 1;
        position.fill = GridBagConstraints.HORIZONTAL;
        position.anchor = GridBagConstraints.NORTHWEST;
        for (var child : children) {
            position.insets = new Insets(position.gridy == 0 ? 0 : gap, 0, 0, 0);
            panel.add(child, position);
            position.gridy++;
        }
        return panel;
    }

    static JPanel alignedField(String text, JComponent input, String reference) {
        var row = new JPanel(new BorderLayout(12, 0));
        var label = new JLabel(text);
        label.setLabelFor(input);
        var size = label.getPreferredSize();
        size.width = Math.max(size.width, label.getFontMetrics(label.getFont()).stringWidth(reference));
        label.setPreferredSize(size);
        row.add(label, BorderLayout.WEST);
        row.add(input, BorderLayout.CENTER);
        return row;
    }

    static JFileChooser fileChooser(boolean importing, String item) {
        var chooser = new JFileChooser();
        chooser.setLocale(Locale.ENGLISH);
        chooser.updateUI();
        chooser.setDialogTitle((importing ? "Import " : "Export ") + item);
        chooser.setApproveButtonText(importing ? "Import" : "Export");
        return chooser;
    }

    static void usePlainTableText(JTable table) {
        var renderer = new DefaultTableCellRenderer();
        renderer.putClientProperty("html.disable", Boolean.TRUE);
        table.setDefaultRenderer(Object.class, renderer);
    }

    static boolean confirm(Component parent, Object message, String title, String action) {
        var pane = new JOptionPane(message, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION,
                null, new Object[]{action, "Cancel"}, "Cancel");
        pane.setLocale(Locale.ENGLISH);
        var dialog = pane.createDialog(parent, title);
        try {
            dialog.setVisible(true);
            return action.equals(pane.getValue());
        } finally {
            dialog.dispose();
        }
    }
}
