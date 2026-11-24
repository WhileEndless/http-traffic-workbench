package trafficworkbench;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;

final class CollectorTab {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private final JPanel root = new JPanel(new BorderLayout(0, 8));
    private final CollectorStore store;
    private final SearchContextMenu menu;
    private final Supplier<CaptureProfile> profile;
    private final ProfileDialog.SaveProfile saveProfile;
    private final ExchangeView exchange;
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final TableRowSorter<Model> sorter = new TableRowSorter<>(model);
    private final JTextField filter = new JTextField(24);
    private final CardLayout archiveLayout = new CardLayout();
    private final JPanel archiveCards = new JPanel(archiveLayout);
    private final JLabel archiveEmpty = new JLabel("Archive is empty", SwingConstants.CENTER);
    private final JLabel count = new JLabel(" ");
    private final JLabel status = new JLabel(" ");
    private final JButton importButton = new JButton("Import archive…");
    private final JButton exportButton = new JButton("Export archive…");
    private final JButton clear = new JButton("Clear archive…");
    private final AtomicBoolean reloadQueued = new AtomicBoolean();
    private final Timer reload = new Timer(500, event -> {
        reloadQueued.set(false);
        refresh();
    });
    private boolean busy;
    private ProfileDialog settings;

    CollectorTab(MontoyaApi api, CollectorStore store, SearchContextMenu menu,
                 Supplier<CaptureProfile> profile, ProfileDialog.SaveProfile saveProfile) {
        this.store = store;
        this.menu = menu;
        this.profile = profile;
        this.saveProfile = saveProfile;
        exchange = new ExchangeView(api);
        build(api);
        api.userInterface().applyThemeToComponent(root);
        reload.setRepeats(false);
        store.setListener(() -> {
            if (reloadQueued.compareAndSet(false, true)) {
                SwingUtilities.invokeLater(reload::start);
            }
        });
        refresh();
    }

    Component uiComponent() { return root; }

    void close() {
        store.setListener(() -> {});
        SwingUtilities.invokeLater(() -> {
            reload.stop();
            if (settings != null) settings.dispose();
        });
    }

    private void build(MontoyaApi api) {
        root.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));
        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.Y_AXIS));
        var heading = new JPanel(new BorderLayout(8, 0));
        heading.setBorder(BorderFactory.createEmptyBorder(3, 0, 8, 0));
        JLabel title = new JLabel(TrafficWorkbench.NAME);
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 5));
        heading.add(title, BorderLayout.WEST);
        var release = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        release.add(new JLabel(BuildInfo.release()));
        JButton info = new JButton("Info");
        info.addActionListener(event -> BuildInfo.show(root));
        release.add(info);
        heading.add(release, BorderLayout.EAST);
        toolbar.add(heading);
        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton history = new JButton("Search all traffic…");
        JButton archive = new JButton("Search archive…");
        archive.setToolTipText("Search traffic saved, imported, or captured by HTTP Traffic Workbench.");
        JButton cookies = new JButton("Trace a cookie…");
        cookies.addActionListener(event -> menu.openCookieTrace(null, null));
        JButton historyLabels = new JButton("Label history…");
        historyLabels.addActionListener(event -> menu.openHistoryLabeler(null));
        JButton config = new JButton("Project settings…");
        history.addActionListener(event -> menu.open(ExtractDialog.Dataset.ALL, ExtractDialog.Context.empty()));
        archive.addActionListener(event -> menu.open(ExtractDialog.Dataset.ARCHIVE, ExtractDialog.Context.empty()));
        config.addActionListener(event -> {
            settings = new ProfileDialog(SwingUtilities.getWindowAncestor(root), profile.get(), saveProfile);
            api.userInterface().applyThemeToComponent(settings.getContentPane());
            settings.setVisible(true);
            settings = null;
            updateStatus();
        });
        for (var button : List.of(history, archive, cookies, historyLabels, config)) searchRow.add(button);
        toolbar.add(searchRow);

        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filterRow.setBorder(BorderFactory.createEmptyBorder(3, 0, 0, 0));
        filter.setToolTipText("User, method, URL, or HTTP status");
        filterRow.add(ExtractDialog.labeled("Archive filter", filter));
        JButton reset = new JButton("Clear");
        reset.addActionListener(event -> {
            filter.setText("");
            filter.requestFocusInWindow();
        });
        filterRow.add(reset);
        filterRow.add(count);
        toolbar.add(filterRow);
        root.add(toolbar, BorderLayout.NORTH);

        var debounce = new Timer(180, event -> applyFilter());
        debounce.setRepeats(false);
        filter.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent event) { debounce.restart(); }
            public void removeUpdate(DocumentEvent event) { debounce.restart(); }
            public void changedUpdate(DocumentEvent event) { debounce.restart(); }
        });

        table.setRowSorter(sorter);
        sorter.setSortKeys(List.of(new RowSorter.SortKey(4, SortOrder.DESCENDING)));
        table.setFillsViewportHeight(true);
        Dialogs.usePlainTableText(table);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(2).setPreferredWidth(450);
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                int selected = table.getSelectedRow();
                exchange.show(selected < 0 ? null : model.entries.get(table.convertRowIndexToModel(selected)).requestResponse());
            }
        });
        archiveEmpty.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        archiveCards.add(new JScrollPane(table), "table");
        archiveCards.add(archiveEmpty, "empty");
        var center = ExchangeView.split(JSplitPane.VERTICAL_SPLIT, archiveCards, exchange.component(), .58);
        root.add(center, BorderLayout.CENTER);

        JPanel footer = new JPanel(new BorderLayout());
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        importButton.addActionListener(event -> transfer(true));
        exportButton.addActionListener(event -> transfer(false));
        clear.addActionListener(event -> {
            if (Dialogs.confirm(root, "Delete the samples in the traffic archive?",
                    "Clear archive", "Delete samples")) {
                store.clear();
                status.setText("Traffic archive cleared.");
            }
        });
        for (var button : List.of(importButton, exportButton, clear)) actions.add(button);
        footer.add(actions, BorderLayout.EAST);
        footer.add(status, BorderLayout.CENTER);
        root.add(footer, BorderLayout.SOUTH);
        updateStatus();
    }

    private void updateStatus() {
        CaptureProfile current = profile.get();
        boolean captureOn = current.collect() || !current.captureTools().isEmpty();
        status.setText(captureOn ? current.persistArchive()
                ? "Capture on · Archive saved to project" : "Capture on · Temporary archive"
                : current.persistArchive() ? "Capture off · Archive saved to project"
                : "Capture off · Proxy history is available to search");
    }

    private void refresh() {
        int selected = table.getSelectedRow();
        var current = selected < 0 ? null : model.entries.get(table.convertRowIndexToModel(selected));
        model.entries = store.all();
        model.fireTableDataChanged();
        if (current != null) {
            int index = model.entries.indexOf(current);
            if (index >= 0) {
                int view = table.convertRowIndexToView(index);
                if (view >= 0) table.setRowSelectionInterval(view, view);
            }
        }
        updateCount();
    }

    private void applyFilter() {
        String needle = filter.getText().strip().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(needle.isEmpty() ? null : new RowFilter<>() {
            @Override public boolean include(Entry<? extends Model, ? extends Integer> row) {
                for (int col = 0; col < 4; col++) {
                    if (row.getStringValue(col).toLowerCase(Locale.ROOT).contains(needle)) return true;
                }
                return false;
            }
        });
        updateCount();
    }

    private void updateCount() {
        count.setText(table.getRowCount() + " shown / " + model.entries.size() + " samples");
        if (table.getRowCount() == 0) {
            archiveEmpty.setText(model.entries.isEmpty()
                    ? "The archive is empty. Enable capture in Project settings or import an archive."
                    : "No archived samples match the filter.");
            archiveLayout.show(archiveCards, "empty");
        } else {
            archiveLayout.show(archiveCards, "table");
        }
        exportButton.setEnabled(!busy && !model.entries.isEmpty());
        clear.setEnabled(!busy && !model.entries.isEmpty());
    }

    private void transfer(boolean importing) {
        JFileChooser chooser = Dialogs.fileChooser(importing, "archive");
        if (importing) {
            chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                    "Traffic archive (TSV) or Burp Logger export (CSV)", "tsv", "csv"));
        }
        if (!importing) chooser.setSelectedFile(new java.io.File("http-traffic-workbench-archive.tsv"));
        int result = importing ? chooser.showOpenDialog(root) : chooser.showSaveDialog(root);
        if (result != JFileChooser.APPROVE_OPTION) return;
        var path = chooser.getSelectedFile().toPath();
        if (importing) {
            task("Reading archive…", () -> {
                var entries = Persistence.importArchive(path);
                int accepted = store.addAll(entries);
                return entries.size() + " samples read · " + accepted + " samples added or updated.";
            });
        } else if (!Files.exists(path) || Dialogs.confirm(root, "Overwrite " + path.getFileName() + "?",
                "Overwrite file", "Overwrite")) {
            var entries = store.all();
            task("Writing archive…", () -> {
                Persistence.exportArchive(path, entries);
                return entries.size() + " samples exported.";
            });
        }
    }

    private void task(String message, Callable<String> task) {
        busy = true;
        importButton.setEnabled(false);
        updateCount();
        status.setText(message);
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() throws Exception { return task.call(); }
            @Override protected void done() {
                busy = false;
                importButton.setEnabled(true);
                refresh();
                try {
                    status.setText(get());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    status.setText("Operation interrupted.");
                } catch (ExecutionException ex) {
                    status.setText("The operation failed. " + ex.getCause().getMessage());
                }
            }
        }.execute();
    }

    private static final class Model extends AbstractTableModel {
        private static final String[] COLUMNS = {"User", "Method", "URL", "HTTP", "Time"};
        private List<CapturedEntry> entries = List.of();
        public int getRowCount() { return entries.size(); }
        public int getColumnCount() { return COLUMNS.length; }
        public String getColumnName(int col) { return COLUMNS[col]; }

        public Object getValueAt(int row, int col) {
            CapturedEntry entry = entries.get(row);
            return switch (col) {
                case 0 -> entry.userCode().isEmpty() ? "—" : entry.userCode();
                case 1 -> entry.method();
                case 2 -> entry.requestResponse().request().url();
                case 3 -> entry.statusCode() == 0 ? "—" : Short.toString(entry.statusCode());
                default -> TIME.format(Instant.ofEpochMilli(entry.time()));
            };
        }
    }
}
