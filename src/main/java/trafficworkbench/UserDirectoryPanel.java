package trafficworkbench;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;

final class UserDirectoryPanel extends JPanel {
    private final JTextField query = new JTextField(20);
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);
    private final JLabel status = new JLabel(" ");
    private final JButton refresh = new JButton("Refresh");
    private final JButton action;
    private final TrafficCatalog catalog;
    private final Supplier<CaptureProfile> profile;
    private SwingWorker<TrafficCatalog.Users, Void> worker;
    private boolean proxyUnavailable;
    private boolean failed;

    UserDirectoryPanel(TrafficCatalog catalog, Supplier<CaptureProfile> profile, JButton action) {
        super(new BorderLayout(0, 8));
        this.catalog = catalog;
        this.profile = profile;
        this.action = action;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        var controls = new JPanel(new BorderLayout(8, 0));
        controls.add(ExtractDialog.labeled("Find user", query), BorderLayout.CENTER);
        controls.add(refresh, BorderLayout.EAST);
        add(controls, BorderLayout.NORTH);
        refresh.addActionListener(event -> refresh(selectedUser()));

        table.setRowSorter(sorter);
        sorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.ASCENDING)));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.getAccessibleContext().setAccessibleName("Captured users");
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(1).setMaxWidth(120);
        Dialogs.usePlainTableText(table);
        table.getSelectionModel().addListSelectionListener(event -> action.setEnabled(!selectedUser().isEmpty()));
        table.getInputMap().put(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, 0), "selectUser");
        table.getActionMap().put("selectUser", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) {
                if (action.isEnabled()) action.doClick();
            }
        });
        var scroll = new JScrollPane(table);
        scroll.setColumnHeaderView(table.getTableHeader());
        add(scroll, BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);
        action.setEnabled(false);
        query.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { filter(); }
            @Override public void removeUpdate(DocumentEvent event) { filter(); }
            @Override public void changedUpdate(DocumentEvent event) { filter(); }
        });
    }

    String selectedUser() {
        int selected = table.getSelectedRow();
        return selected < 0 ? "" : model.users.get(table.convertRowIndexToModel(selected)).label();
    }

    void focusSearch() {
        query.requestFocusInWindow();
    }

    void refresh(String user) {
        if (worker != null) return;
        CaptureProfile settings = profile.get();
        refresh.setEnabled(false);
        failed = false;
        worker = new SwingWorker<>() {
            @Override protected TrafficCatalog.Users doInBackground() {
                return catalog.users(settings, this::isCancelled);
            }

            @Override protected void done() {
                if (worker != this) return;
                String selected = selectedUser();
                worker = null;
                refresh.setEnabled(true);
                try {
                    var result = get();
                    model.users = result.entries();
                    proxyUnavailable = result.proxyUnavailable();
                    model.fireTableDataChanged();
                    selectUser(selected.isEmpty() ? user : selected);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    failed = true;
                } catch (ExecutionException | CancellationException ex) {
                    failed = true;
                }
                updateStatus();
            }
        };
        updateStatus();
        worker.execute();
    }

    void cancel() {
        if (worker == null) return;
        var active = worker;
        worker = null;
        active.cancel(true);
        refresh.setEnabled(true);
        updateStatus();
    }

    private void selectUser(String user) {
        for (int i = 0; i < model.users.size(); i++) {
            if (!model.users.get(i).label().equals(user)) continue;
            int row = table.convertRowIndexToView(i);
            if (row >= 0) {
                table.setRowSelectionInterval(row, row);
                table.scrollRectToVisible(table.getCellRect(row, 0, true));
            }
            return;
        }
    }

    private void filter() {
        String needle = query.getText().strip().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(needle.isEmpty() ? null : new RowFilter<>() {
            @Override public boolean include(Entry<? extends Model, ? extends Integer> entry) {
                return entry.getStringValue(0).toLowerCase(Locale.ROOT).contains(needle);
            }
        });
        action.setEnabled(!selectedUser().isEmpty());
        updateStatus();
    }

    private void updateStatus() {
        int shown = table.getRowCount();
        int total = model.users.size();
        String message = worker != null ? "Reading user labels…"
                : failed ? "Could not read user labels. Select Refresh to retry."
                : total == 0 ? "No labeled users found."
                : shown == 0 ? "No users match your search."
                : shown + " shown / " + total + " users";
        if (proxyUnavailable && worker == null && !failed) message += " Proxy history unavailable.";
        status.setText(message);
    }

    private static final class Model extends AbstractTableModel {
        private List<TrafficCatalog.UserCount> users = List.of();

        @Override public int getRowCount() { return users.size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int column) { return column == 0 ? "User" : "Records"; }
        @Override public Class<?> getColumnClass(int column) { return column == 0 ? String.class : Integer.class; }
        @Override public Object getValueAt(int row, int column) {
            var user = users.get(row);
            return column == 0 ? user.label() : user.records();
        }
    }
}
