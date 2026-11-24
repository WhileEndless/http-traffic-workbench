package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import trafficworkbench.ExtractDialog.Context;
import trafficworkbench.ExtractDialog.Dataset;

import static trafficworkbench.ExtractDialog.labeled;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import java.util.regex.Pattern;

final class SearchPanel extends JPanel {
    private enum Mode {
        AUTO("Auto"), KEY("Field name"), VALUE("Field value"), TEXT("Text"), COOKIE("Exact cookie match"), COOKIE_ROTATION("Proxy replacement trace");
        private final String label;
        Mode(String label) { this.label = label; }
        public String toString() { return label; }
    }

    private static final String[] COLUMNS = {"Relevance", "User", "URL", "Tool", "Side", "Field", "Value", "Match"};

    private final MontoyaApi api;
    private final CollectorStore store;
    private final ScanQueue scans;
    private final Supplier<CaptureProfile> profile;
    private final Context context;
    private final SourcePicker sources;
    private final JComboBox<Mode> mode = new JComboBox<>(new Mode[]{Mode.AUTO, Mode.KEY, Mode.VALUE, Mode.TEXT});
    private final JComboBox<ExtractEngine.Direction> direction = new JComboBox<>(ExtractEngine.Direction.values());
    private final JTextField query = new JTextField(24);
    private final JTextField url = new JTextField(14);
    private final JTextField methods = new JTextField(9);
    private final JTextField statuses = new JTextField(9);
    private final JTextField mimeTypes = new JTextField(9);
    private final JTextField extensions = new JTextField(9);
    private final JTextField listener = new JTextField(6);
    private final JCheckBox responsesOnly = new JCheckBox("With responses");
    private final JCheckBox parametersOnly = new JCheckBox("With parameters");
    private final JCheckBox annotatedOnly = new JCheckBox("With annotations");
    private final JCheckBox regex = new JCheckBox("Regex");
    private final JCheckBox negative = new JCheckBox("Exclude matches");
    private final JCheckBox scope = new JCheckBox("Limit to Burp scope");
    private final JCheckBox caseSensitive = new JCheckBox("Case-sensitive text");
    private final JCheckBox partial = new JCheckBox("Partial value matches", true);
    private final JCheckBox collapseRepeated = new JCheckBox("Collapse repeated matches");
    private final JCheckBox sameHost = new JCheckBox("Same host", true);
    private final JCheckBox siblings = new JCheckBox("Neighboring fields");
    private final JSpinner depth = new JSpinner(new SpinnerNumberModel(1, 0, 3, 1));
    private final JCheckBox tabSeparator = new JCheckBox("Tab-separated", true);
    private final JLabel status = new JLabel("Ready to search.");
    private final JLabel pageLabel = new JLabel("0 results");
    private final JButton previous = new JButton("Previous");
    private final JButton next = new JButton("Next");
    private final JButton search = new JButton("Search");
    private final JButton browse = new JButton("Browse traffic");
    private final JButton stop = new JButton("Stop");
    private final JButton copy = new JButton("Copy selected");
    private final JButton copyPage = new JButton("Copy page");
    private final JProgressBar progress = new JProgressBar(0, 100);
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final CardLayout resultLayout = new CardLayout();
    private final JPanel resultCards = new JPanel(resultLayout);
    private final JLabel emptyResults = new JLabel("Enter a search term or select Browse traffic.", SwingConstants.CENTER);
    private final ExchangeView editors;
    private final Timer previewTimer = new Timer(120, event -> showPreview());
    private ResultRow selectedPreview;
    private ResultRow displayedPreview;
    private burp.api.montoya.http.message.HttpRequestResponse displayedExchange;
    private final Timer responseRefresh = new Timer(400, event -> waitForResponse());
    private int responseChecks;
    private final JComboBox<ResultPages.Filter> resultFilter = new JComboBox<>(ResultPages.Filter.values());
    private final ResultPages pages = new ResultPages();
    private SearchWorker worker;
    private Set<TrafficSource> lastSources;
    private boolean updatingPage;
    private int page;
    private String referenceHost = "";

    SearchPanel(MontoyaApi api, CollectorStore store, ScanQueue scans, Supplier<CaptureProfile> profile,
                Dataset initialDataset, Context context, Runnable closeDialog) {
        super(new BorderLayout(0, 8));
        this.api = api;
        this.store = store;
        this.scans = scans;
        this.profile = profile;
        this.context = context;
        var selectedRequest = context.selectedExchange() == null ? null : context.selectedExchange().exchange().request();
        setReferenceHost(selectedRequest == null ? null : selectedRequest.httpService());
        sameHost.setVisible(context.cookie() == null);
        Set<TrafficSource> allowedSources = context.cookie() != null && context.cookie().followReplacements()
                ? Set.of(TrafficSource.PROXY) : java.util.EnumSet.allOf(TrafficSource.class);
        sources = new SourcePicker("Sources", allowedSources, initialDataset.sources());
        sources.whenClosed(this::sourcesChanged);
        if (initialDataset == Dataset.ARCHIVE) status.setText("Search saved, imported, or captured traffic.");
        resultFilter.setSelectedItem(ResultPages.Filter.ALL);
        query.setText(context.selection());
        mode.setSelectedItem(Mode.AUTO);
        if (context.cookie() != null) {
            Mode cookieMode = context.cookie().followReplacements() ? Mode.COOKIE_ROTATION : Mode.COOKIE;
            mode.addItem(cookieMode);
            mode.setSelectedItem(cookieMode);
            search.setText("Trace cookie");
            mode.setEnabled(false);
            query.setEditable(false);
            query.setText(context.cookie().name());
            query.setToolTipText(context.cookie().followReplacements()
                    ? "Matching and following replacements in chronological Proxy history."
                    : "The cookie value is hidden. Use Sources and Advanced to narrow the trace.");
            status.setText("Tracing the selected cookie across the chosen HTTP sources.");
        }
        editors = new ExchangeView(api);
        previewTimer.setRepeats(false);
        build(closeDialog);
    }

    void searchSelection() {
        if (hasSearchTerm()) {
            search();
        } else {
            query.requestFocusInWindow();
        }
    }

    private void build(Runnable closeDialog) {
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        var clear = new JButton("Clear");
        clear.setVisible(context.cookie() == null);
        var close = new JButton("Close");
        clear.addActionListener(event -> {
            query.setText("");
            resetSearch();
            query.requestFocusInWindow();
        });
        search.addActionListener(event -> {
            if (hasSearchTerm()) search();
        });
        browse.addActionListener(event -> {
            if (!hasSearchTerm()) search();
        });
        setSearchRunning(false);
        stop.addActionListener(event -> cancel());
        sameHost.addActionListener(event -> {
            if (lastSources != null) refreshSearch();
        });
        close.addActionListener(event -> closeDialog.run());
        mode.addActionListener(event -> updateOptions());

        JPanel advanced = new JPanel(new GridBagLayout());
        var toggle = new JToggleButton("Advanced");
        var searchActions = new JPanel(new GridBagLayout());
        var actionLayout = new CardLayout();
        var searchAction = new JPanel(actionLayout);
        searchAction.add(search, "search");
        searchAction.add(browse, "browse");
        Runnable updateSearchAction = () -> {
            boolean hasTerm = hasSearchTerm();
            search.setEnabled(hasTerm);
            actionLayout.show(searchAction, hasTerm ? "search" : "browse");
            if (!hasTerm && lastSources != null) resetSearch();
        };
        query.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { updateSearchAction.run(); }
            @Override public void removeUpdate(DocumentEvent event) { updateSearchAction.run(); }
            @Override public void changedUpdate(DocumentEvent event) { updateSearchAction.run(); }
        });
        updateSearchAction.run();
        var action = new GridBagConstraints();
        action.insets = new Insets(0, 0, 0, 8);
        searchActions.add(searchAction, action);
        action.insets = new Insets(0, 0, 0, 0);
        searchActions.add(clear, action);
        var searchBox = new JPanel(new BorderLayout(12, 0));
        var queryLabel = new JLabel(context.cookie() == null ? "Search term" : "Cookie name");
        queryLabel.setLabelFor(query);
        searchBox.add(query, BorderLayout.CENTER);
        searchBox.add(searchActions, BorderLayout.EAST);
        var form = new JPanel(new BorderLayout(0, 6));
        form.add(queryLabel, BorderLayout.NORTH);
        form.add(searchBox, BorderLayout.CENTER);

        var basicOptions = new JPanel(new GridBagLayout());
        var position = new GridBagConstraints();
        position.gridy = 0;
        position.anchor = GridBagConstraints.WEST;
        position.insets = new Insets(0, 0, 0, 12);
        for (var control : List.of(sources, sameHost, labeled("Mode", mode), labeled("Depth", depth))) {
            basicOptions.add(control, position);
        }
        position.weightx = 1;
        position.insets = new Insets(0, 0, 0, 0);
        basicOptions.add(Box.createHorizontalGlue(), position);
        position.weightx = 0;
        basicOptions.add(toggle, position);
        formRow(advanced, 0, labeled("URL contains", url), labeled("Direction", direction), scope);
        formRow(advanced, 1, labeled("Method", methods), labeled("Status", statuses), labeled("MIME type", mimeTypes));
        formRow(advanced, 2, labeled("Extension", extensions), labeled("Listener port", listener), responsesOnly);
        formRow(advanced, 3, parametersOnly, annotatedOnly, collapseRepeated);
        formRow(advanced, 4, partial, siblings, caseSensitive);
        var resetFilters = new JButton("Reset filters");
        resetFilters.addActionListener(event -> {
            for (var field : List.of(url, methods, statuses, mimeTypes, extensions, listener)) field.setText("");
            for (var option : List.of(scope, responsesOnly, parametersOnly, annotatedOnly, regex, negative,
                    siblings, caseSensitive)) option.setSelected(false);
            partial.setSelected(true);
            collapseRepeated.setSelected(false);
            direction.setSelectedItem(ExtractEngine.Direction.BOTH);
        });
        formRow(advanced, 5, regex, negative, resetFilters);
        methods.setToolTipText("Comma-separated methods such as GET, POST.");
        statuses.setToolTipText("Use exact codes, families such as 2xx, or none.");
        mimeTypes.setToolTipText("Enter types such as json, image/, or text/html.");
        extensions.setToolTipText("Use comma-separated extensions or none.");
        listener.setToolTipText("Match a listener port recorded in Proxy history.");
        regex.addActionListener(event -> {
            if (regex.isSelected()) mode.setSelectedItem(Mode.TEXT);
        });
        negative.addActionListener(event -> {
            if (negative.isSelected()) mode.setSelectedItem(Mode.TEXT);
        });
        depth.setToolTipText("Use 0 for direct matches. Depths 1–3 follow shared values to related fields.");
        partial.setToolTipText("Include matches inside field values. Auto can also match plain text.");
        collapseRepeated.setToolTipText("Show one example of the same match per user, endpoint, and message direction.");
        var moreFilters = new JScrollPane(advanced, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        moreFilters.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        moreFilters.getVerticalScrollBar().setUnitIncrement(16);
        moreFilters.setPreferredSize(new Dimension(1, 172));
        var advancedSection = new JPanel(new BorderLayout(0, 3));
        advancedSection.add(new JSeparator(), BorderLayout.NORTH);
        advancedSection.add(moreFilters, BorderLayout.CENTER);
        advancedSection.setVisible(false);
        toggle.addActionListener(event -> advancedSection.setVisible(toggle.isSelected()));
        var toolbar = Dialogs.stack(12, form, basicOptions, advancedSection);
        toolbar.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        add(toolbar, BorderLayout.NORTH);

        table.setFillsViewportHeight(true);
        table.setDefaultRenderer(Object.class, new SearchResultRenderer(false));
        table.getAccessibleContext().setAccessibleName("Search results");
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        int[] widths = {64, 95, 230, 112, 70, 135, 170, 147};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        table.getColumnModel().getColumn(0).setCellRenderer(new SearchResultRenderer(true));
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && !updatingPage) {
                queuePreview();
            }
        });
        var results = new JPanel(new BorderLayout(0, 4));
        var resultTools = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        resultTools.add(labeled("Results", resultFilter));
        resultFilter.addActionListener(event -> showPage(0));
        results.add(resultTools, BorderLayout.NORTH);
        var tableView = new JScrollPane(table);
        tableView.setColumnHeaderView(table.getTableHeader());
        resultCards.add(tableView, "table");
        resultCards.add(emptyResults, "empty");
        results.add(resultCards, BorderLayout.CENTER);
        JSplitPane split = ExchangeView.split(JSplitPane.VERTICAL_SPLIT, results, editors.component(), .55);
        add(split, BorderLayout.CENTER);

        JPanel footer = new JPanel(new BorderLayout(0, 4));
        JPanel feedback = new JPanel(new BorderLayout(8, 0));
        progress.setPreferredSize(new Dimension(105, 16));
        progress.getAccessibleContext().setAccessibleName("Search progress");
        var progressControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        progressControls.add(progress);
        progressControls.add(stop);
        feedback.add(status, BorderLayout.CENTER);
        feedback.add(progressControls, BorderLayout.EAST);
        feedback.setPreferredSize(new Dimension(1, Math.max(stop.getPreferredSize().height, status.getPreferredSize().height)));
        footer.add(feedback, BorderLayout.NORTH);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        previous.addActionListener(event -> showPage(page - 1));
        next.addActionListener(event -> showPage(page + 1));
        copy.addActionListener(event -> copy(true));
        copyPage.addActionListener(event -> copy(false));
        for (var component : List.of(previous, next, pageLabel, copy, copyPage, tabSeparator, close)) {
            buttons.add(component);
        }
        footer.add(buttons, BorderLayout.SOUTH);
        add(footer, BorderLayout.SOUTH);

        showPage(0);
        updateOptions();
    }

    private static void formRow(JPanel form, int row, JComponent... components) {
        var constraints = new GridBagConstraints();
        constraints.gridy = row;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(2, 0, 4, 8);
        for (int col = 0; col < components.length; col++) {
            constraints.gridx = col;
            constraints.weightx = col == 0 ? 1 : 0;
            form.add(components[col], constraints);
        }
    }

    private void updateOptions() {
        boolean text = mode.getSelectedItem() == Mode.TEXT;
        boolean cookie = context.cookie() != null;
        collapseRepeated.setEnabled(!cookie);
        regex.setEnabled(!cookie);
        negative.setEnabled(!cookie);
        caseSensitive.setEnabled(text || mode.getSelectedItem() == Mode.AUTO);
        partial.setEnabled(!cookie && !text && mode.getSelectedItem() != Mode.KEY);
        siblings.setEnabled(partial.isEnabled());
        depth.setEnabled(!cookie && !text);
        if (!text) {
            regex.setSelected(false);
            negative.setSelected(false);
        }
    }

    private void sourcesChanged() {
        if (lastSources == null || lastSources.equals(sources.selected())) return;
        if (sources.selected().isEmpty()) {
            resetSearch();
            emptyResults.setText("Select at least one traffic source.");
            status.setText("No traffic sources selected.");
            return;
        }
        refreshSearch();
    }

    private boolean hasSearchTerm() {
        return context.cookie() != null || !query.getText().isBlank();
    }

    private void refreshSearch() {
        if (hasSearchTerm()) search();
        else resetSearch();
    }

    private void resetSearch() {
        lastSources = null;
        cancel();
        pages.clear();
        showPage(0);
        status.setText("Ready to search.");
        emptyResults.setText("Enter a search term or select Browse traffic.");
    }

    private void search() {
        String needle = query.getText().strip();
        if (needle.length() > 8192) {
            status.setText("Search terms can be up to 8,192 characters.");
            return;
        }
        if (sources.selected().isEmpty()) {
            status.setText("Select at least one source.");
            sources.requestFocusInWindow();
            return;
        }
        Mode selectedMode = (Mode) mode.getSelectedItem();
        boolean exclude = !needle.isEmpty() && selectedMode == Mode.TEXT && negative.isSelected();
        boolean regexSearch = !needle.isEmpty() && selectedMode == Mode.TEXT && regex.isSelected();
        Pattern expression = null;
        TrafficFilters traffic;
        try {
            if (regexSearch) {
                expression = TimedRegex.compile(needle, caseSensitive.isSelected()
                        ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
            } else if (exclude) {
                expression = Pattern.compile(needle, Pattern.LITERAL | (caseSensitive.isSelected()
                        ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE));
            }
            traffic = TrafficFilters.create(url.getText(), scope.isSelected(), responsesOnly.isSelected(),
                    parametersOnly.isSelected(), annotatedOnly.isSelected(), methods.getText(), statuses.getText(),
                    mimeTypes.getText(), extensions.getText(), listener.getText());
        } catch (IllegalArgumentException ex) {
            status.setText(ex instanceof java.util.regex.PatternSyntaxException syntax
                    ? "Invalid regex. " + syntax.getDescription() : ex.getMessage());
            return;
        }
        cancel();
        lastSources = sources.selected();
        Options options = new Options(lastSources, selectedMode,
                (ExtractEngine.Direction) direction.getSelectedItem(), needle, traffic, caseSensitive.isSelected(),
                partial.isSelected(), siblings.isSelected(), context.cookie() == null && collapseRepeated.isSelected(),
                context.cookie() == null ? (Integer) depth.getValue() : 0,
                profile.get().notePrefix(), sameHost.isEnabled() && sameHost.isSelected() ? referenceHost : "",
                expression, regexSearch, exclude);
        pages.clear();
        showPage(0);
        status.setText(needle.isEmpty() ? "Preparing to browse traffic…" : "Preparing search…");
        emptyResults.setText(needle.isEmpty() ? "Waiting for traffic…" : "Waiting for matches…");
        setSearchRunning(true);
        worker = new SearchWorker(options);
        var active = worker;
        worker.addPropertyChangeListener(event -> {
            if (active == worker && "progress".equals(event.getPropertyName())) {
                status.setText(active.phase + " · " + matchSummary());
                progress.setIndeterminate(false);
                progress.setValue((Integer) event.getNewValue());
            }
        });
        if (!scans.submit(worker)) {
            cancel();
            status.setText("The scan queue is full. Stop a scan and try again.");
        } else {
            active.refreshTimer.start();
        }
    }

    private void cancel() {
        if (worker != null) {
            var active = worker;
            active.refreshTimer.stop();
            worker = null;
            scans.cancel(active);
            updatePage(page, true);
            status.setText("Search stopped · " + matchSummary() + " retained.");
            if (pages.size(ResultPages.Filter.ALL) == 0) emptyResults.setText("Search stopped.");
        }
        setSearchRunning(false);
    }

    private void setSearchRunning(boolean running) {
        progress.setIndeterminate(running);
        progress.setValue(0);
        progress.setVisible(running);
        stop.setVisible(running);
        stop.setEnabled(running);
    }

    private void setReferenceHost(HttpService service) {
        referenceHost = service == null ? "" : service.host();
        sameHost.setEnabled(context.cookie() == null && !referenceHost.isEmpty());
        sameHost.setToolTipText(referenceHost.isEmpty() ? "Select an HTTP result or open search from a message to choose a host."
                : "Search " + referenceHost + " across paths, ports, and protocols.");
    }

    void bindDefaultAction(JRootPane root) {
        root.setDefaultButton(search);
    }

    private String matchSummary() {
        int direct = pages.size(ResultPages.Filter.DIRECT);
        int related = pages.size(ResultPages.Filter.RELATED);
        return related == 0 ? direct + " matches" : direct + " direct · " + related + " related";
    }

    void close() {
        lastSources = null;
        cancel();
        previewTimer.stop();
        responseRefresh.stop();
        selectedPreview = null;
        displayedPreview = null;
        editors.show(null);
    }

    void windowFocused() {
        if (selectedPreview != displayedPreview || selectedPreview != null
                && selectedPreview.entry.latest().requestResponse() != displayedExchange) {
            previewTimer.restart();
        }
    }

    private void queuePreview() {
        int selected = table.getSelectedRow();
        copy.setEnabled(selected >= 0);
        ResultRow row = selected < 0 ? null : model.current.get(selected);
        if (row != null && context.selectedExchange() == null && context.cookie() == null) {
            setReferenceHost(row.entry.requestResponse().request().httpService());
        }
        if (row == selectedPreview) return;
        responseRefresh.stop();
        selectedPreview = row;
        previewTimer.restart();
    }

    private void showPreview() {
        var row = selectedPreview;
        var exchange = row == null ? null : row.entry.latest().requestResponse();
        if (row == displayedPreview && exchange == displayedExchange) return;
        var window = SwingUtilities.getWindowAncestor(this);
        if (window != null && !window.isFocused()) return;
        boolean keepTableFocus = table.isFocusOwner();
        String requestMatch = row != null && row.source.equals("Request") ? row.editorSearch : "";
        String responseMatch = row != null && row.source.equals("Response") ? row.editorSearch : "";
        editors.show(exchange, requestMatch, responseMatch);
        displayedPreview = row;
        displayedExchange = exchange;
        if (keepTableFocus) table.requestFocusInWindow();
        if (row != null && row.entry.awaitingResponse()) {
            responseChecks = 25;
            responseRefresh.restart();
        }
    }

    private void waitForResponse() {
        var row = selectedPreview;
        if (row == null || !row.entry.awaitingResponse() || --responseChecks <= 0) {
            responseRefresh.stop();
            showPreview();
        }
    }

    private void showPage(int index) {
        updatePage(index, false);
    }

    private void updatePage(int index, boolean preserveSelection) {
        page = index;
        var filter = (ResultPages.Filter) resultFilter.getSelectedItem();
        var visible = pages.page(filter, index);
        if (!model.current.equals(visible) || !preserveSelection) {
            var selected = preserveSelection
                    ? Arrays.stream(table.getSelectedRows()).mapToObj(indexInPage -> model.current.get(indexInPage).id)
                            .collect(java.util.stream.Collectors.toSet()) : Set.<Integer>of();
            updatingPage = true;
            try {
                table.clearSelection();
                model.current = visible;
                model.fireTableDataChanged();
                for (int i = 0; i < visible.size(); i++) {
                    if (selected.contains(visible.get(i).id)) table.addRowSelectionInterval(i, i);
                }
            } finally {
                updatingPage = false;
            }
            queuePreview();
        }
        int total = pages.size(filter);
        if (visible.isEmpty() && pages.size(ResultPages.Filter.ALL) > 0) {
            emptyResults.setText(worker == null ? "No matches in this view." : "Waiting for matches in this view…");
        }
        resultLayout.show(resultCards, visible.isEmpty() ? "empty" : "table");
        int from = index * ResultPages.PAGE_SIZE;
        previous.setEnabled(index > 0);
        next.setEnabled(from + visible.size() < total && !visible.isEmpty());
        copyPage.setEnabled(!visible.isEmpty());
        pageLabel.setText(visible.isEmpty() ? "0 results" : (from + 1) + "–" + (from + visible.size()) + " / " + total);
    }

    private void copy(boolean selectedOnly) {
        int[] indices = selectedOnly ? table.getSelectedRows()
                : java.util.stream.IntStream.range(0, model.current.size()).toArray();
        String separator = tabSeparator.isSelected() ? "\t" : ", ";
        StringBuilder out = new StringBuilder(String.join(separator, COLUMNS)).append('\n');
        for (int row : indices) {
            for (int col = 0; col < COLUMNS.length; col++) {
                if (col > 0) {
                    out.append(separator);
                }
                String value = model.getValueAt(row, col).toString().replace('\r', ' ').replace('\n', ' ');
                if (value.contains(separator) || value.contains("\"")) {
                    out.append('"').append(value.replace("\"", "\"\"")).append('"');
                } else {
                    out.append(value);
                }
            }
            out.append('\n');
        }
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(out.toString()), null);
            status.setText(indices.length + " rows copied to the clipboard.");
        } catch (IllegalStateException ex) {
            status.setText("The clipboard is busy. Try again.");
        }
    }

    private record Options(Set<TrafficSource> sources, Mode mode, ExtractEngine.Direction direction, String needle,
                           TrafficFilters traffic, boolean caseSensitive, boolean partial, boolean siblings,
                           boolean collapseRepeated, int depth, String notePrefix, String host, Pattern expression,
                           boolean regex, boolean exclude) {}

    private record SearchResults(int scanned, boolean limited) {}

    private final class SearchWorker extends SwingWorker<SearchResults, List<ResultRow>> implements ExtractEngine.Sink {
        private final Options options;
        private final ResultBatches batches = new ResultBatches(this::publish);
        private final Timer refreshTimer = new Timer(100, event -> refreshResults());
        private boolean firstBatch = true;
        private boolean pageDirty;
        private boolean countedScan;
        private volatile int scanned;
        private volatile String phase = "Reading selected sources";

        private SearchWorker(Options options) {
            this.options = options;
        }

        @Override protected SearchResults doInBackground() {
            Iterable<CapturedEntry> entries = loadEntries();
            var engine = new ExtractEngine(entries, -1, context.path(), options.depth(), options.siblings(),
                    options.direction(), options.partial(), options.collapseRepeated(), this);
            if (options.needle().isEmpty()) {
                engine.browse();
                batches.flush();
                return new SearchResults(scanned, engine.truncated());
            }
            Mode selected = options.mode();
            switch (selected) {
                case KEY -> engine.runKeyFromContext(Arrays.stream(options.needle().split("[,\\n]"))
                        .map(String::strip).filter(key -> !key.isEmpty()).distinct().toList(),
                        options.depth() > 0 || options.needle().indexOf('%') >= 0 ? context.fields().get() : List.of());
                case VALUE -> engine.runValueFromContext(options.needle(),
                        options.depth() > 0 || options.needle().indexOf('%') >= 0 ? context.fields().get() : List.of());
                case TEXT -> {
                    if (options.expression() == null) engine.runText(options.needle(), options.caseSensitive());
                    else engine.runText(options.expression(), options.regex(), options.exclude());
                }
                case AUTO -> engine.runAutoFromContext(options.needle(), context.fields().get(), options.caseSensitive());
                case COOKIE, COOKIE_ROTATION -> engine.runCookie(context.cookie(), options.traffic()::matches);
            }
            batches.flush();
            return new SearchResults(scanned, engine.truncated() || engine.discoveryLimited());
        }

        private Iterable<CapturedEntry> loadEntries() {
            return () -> {
                var records = new TrafficCatalog(api, store).stream(options.sources(), options.notePrefix(), options.host());
                if (context.cookie() != null) {
                    records = records.takeWhile(entry -> !isCancelled()).filter(entry ->
                            context.cookie().appliesTo(entry.requestResponse().request().httpService()));
                    if (context.cookie().followReplacements()) {
                        records = records.sorted(java.util.Comparator.comparingLong(CapturedEntry::time));
                    } else {
                        records = records.filter(options.traffic()::matches);
                    }
                } else {
                    records = records.filter(options.traffic()::matches);
                    var selected = context.selectedExchange();
                    if (selected != null && options.sources().contains(selected.source())) {
                        var active = selected.entry(options.notePrefix());
                        if (active != null && TrafficCatalog.matchesHost(options.host(), active.requestResponse().request().httpService())
                                && options.traffic().matches(active)) {
                            records = TrafficCatalog.includeSelected(records, active);
                        }
                    }
                }
                if (countedScan) return records.iterator();
                countedScan = true;
                return records.peek(entry -> scanned++).iterator();
            };
        }

        @Override public void row(ResultRow row) { batches.add(row); }
        @Override public void progress(String phase, int done, int total) {
            this.phase = phase;
            batches.flushIfDue();
            if (total > 0 && done <= total) setProgress((int) (100L * done / total));
        }

        @Override protected void process(List<List<ResultRow>> chunks) {
            if (worker != this) return;
            for (var batch : chunks) pages.add(batch);
            pageDirty = true;
            if (firstBatch) {
                firstBatch = false;
                refreshResults();
            }
        }

        private void refreshResults() {
            if (worker != this) return;
            if (pageDirty) {
                pageDirty = false;
                updatePage(page, true);
            }
            String update = phase + " · " + scanned + " records scanned · " + matchSummary();
            if (!update.equals(status.getText())) status.setText(update);
        }

        @Override public boolean cancelled() { return isCancelled(); }

        @Override protected void done() {
            if (worker != this) {
                return;
            }
            refreshTimer.stop();
            worker = null;
            setSearchRunning(false);
            updatePage(page, true);
            try {
                SearchResults result = get();
                if (pages.size(ResultPages.Filter.ALL) == 0) {
                    if (result.scanned() == 0 && options.sources().stream()
                            .allMatch(source -> source == TrafficSource.ARCHIVE || source.toolTraffic())) {
                        emptyResults.setText("No archive traffic matched. Choose Proxy history in Sources to search recorded traffic.");
                    } else {
                        emptyResults.setText(options.needle().isEmpty()
                                ? "No traffic matches the selected filters." : "No matches. Try another search term.");
                    }
                }
                status.setText(matchSummary() + " · " + result.scanned() + " records scanned"
                        + (result.limited() ? " · Search limit reached" : ""));
            } catch (CancellationException ignored) {
                status.setText("Search stopped.");
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                status.setText("Search stopped.");
            } catch (ExecutionException ex) {
                status.setText("Search failed. See the extension error log.");
                if (pages.size(ResultPages.Filter.ALL) == 0) emptyResults.setText("Search failed.");
                api.logging().logToError("Traffic search failed.", ex.getCause());
            }
        }
    }

    private static final class Model extends AbstractTableModel {
        private List<ResultRow> current = List.of();
        public int getRowCount() { return current.size(); }
        public int getColumnCount() { return COLUMNS.length; }
        public String getColumnName(int col) { return COLUMNS[col]; }

        public Object getValueAt(int row, int col) {
            ResultRow match = current.get(row);
            return switch (col) {
                case 0 -> match.relevance;
                case 1 -> match.userCode.isEmpty() ? "—" : match.userCode;
                case 2 -> match.endpoint;
                case 3 -> match.entry.source().label;
                case 4 -> match.source;
                case 5 -> match.key;
                case 6 -> match.value;
                default -> match.reason;
            };
        }
    }
}
