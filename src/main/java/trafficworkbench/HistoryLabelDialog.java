package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.regex.Pattern;

final class HistoryLabelDialog extends JDialog {
    private final MontoyaApi api;
    private final ScanQueue scans;
    private final java.util.function.Supplier<CaptureProfile> profile;
    private final ProfileDialog.SaveProfile saveProfile;
    private final SessionAnchor anchor;
    private final ExchangeView anchorView;
    private final JTabbedPane details = new JTabbedPane();
    private final JCheckBox onlySelected = new JCheckBox("Preview only the selected session", true);
    private final JLabel selectedStatus = new JLabel(" ");
    private final JButton reloadAnchor = new JButton("Reload selected exchange");
    private final JLabel identifierSample = new JLabel(" ");
    private final JLabel cookieSource = new JLabel(" ");
    private SessionSuggestions suggestions;
    private boolean loadingOptions;
    private final JTextField host = new JTextField(25);
    private final JCheckBox scope = new JCheckBox("Limit to Burp scope");
    private final JTextField method = new JTextField(8);
    private final JTextField start = new JTextField(25);
    private final LogoutFields logout = new LogoutFields(true);
    private final JComboBox<CaptureProfile.Source> source = new JComboBox<>(CaptureProfile.Source.values());
    private final JComboBox<String> field = new JComboBox<>();
    private final JComboBox<String> cookie = new JComboBox<>();
    private final JCheckBox live = new JCheckBox("Label new Proxy records automatically");
    private final DefaultTableModel sample = new DefaultTableModel(new String[]{"URL", "Proposed user label"}, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private final JLabel status = new JLabel("Set the login route, user field, and cookie name.");
    private final JProgressBar progress = new JProgressBar(0, 100);
    private final JButton preview = new JButton("Preview");
    private final JButton apply = new JButton("Apply notes");
    private final JButton save = new JButton("Save rule to project");
    private final JButton cancel = new JButton("Stop scan");
    private final JButton close = new JButton("Close");
    private SwingWorker<?, Void> task;
    private HistoryLabeler.Plan plan;
    private boolean editable = true;

    HistoryLabelDialog(MontoyaApi api, ScanQueue scans, java.util.function.Supplier<CaptureProfile> profile, ProfileDialog.SaveProfile saveProfile,
                       SessionAnchor anchor) {
        super(api.userInterface().swingUtils().suiteFrame(), "HTTP Traffic Workbench · Label history", false);
        this.api = api;
        this.scans = scans;
        this.profile = profile;
        var base = profile.get();
        this.saveProfile = saveProfile;
        this.anchor = anchor;
        anchorView = anchor == null ? null : new ExchangeView(api);
        HttpRequestResponse exchange = anchor == null ? null : anchor.exchange();
        field.setEditable(true);
        cookie.setEditable(true);
        field.setPrototypeDisplayValue("xxxxxxxxxxxxxxxxxxxxxx");
        cookie.setPrototypeDisplayValue("xxxxxxxxxxxxxxxxxxxxxx");
        host.setText(anchor == null ? base.hosts() : exchange.request().httpService().host());
        scope.setSelected(anchor == null && base.inScope());
        method.setText(anchor == null ? base.identityMethod() : exchange.request().method());
        start.setText(anchor == null ? base.identityPath() : exchange.request().pathWithoutQuery());
        logout.setRule(base.logout());
        source.setSelectedItem(base.source());
        if (base.locator() == CaptureProfile.Locator.FIELD) setValue(field, base.expression());
        setValue(cookie, base.sessionCookie());
        live.setSelected(base.annotate());
        build();
        if (anchor != null) suggest();
    }

    private void build() {
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));
        var fields = new java.util.ArrayList<JComponent>();
        var target = new JPanel(new BorderLayout(12, 0));
        target.add(Dialogs.alignedField("Host", host, "User identifier source"));
        target.add(scope, BorderLayout.EAST);
        var login = new JPanel(new BorderLayout(12, 0));
        login.add(Dialogs.alignedField("Login path", start, "User identifier source"));
        login.add(ExtractDialog.labeled("Method", method), BorderLayout.EAST);
        fields.add(target);
        fields.add(login);
        if (!profile.get().identityRequestBody().isBlank()) {
            fields.add(new JLabel("A login body condition is set in Project settings."));
        }
        fields.add(Dialogs.alignedField("User identifier source", source, "User identifier source"));
        fields.add(Dialogs.alignedField("User identifier field", field, "User identifier source"));
        fields.add(Dialogs.alignedField("Session cookie name", cookie, "User identifier source"));
        fields.addAll(logout.rows("Logout HTTP method", false));
        fields.add(live);
        if (anchor != null) {
            fields.add(onlySelected);
            var selectedDetails = new JPanel(new BorderLayout(8, 0));
            selectedDetails.add(selectedStatus, BorderLayout.CENTER);
            selectedDetails.add(reloadAnchor, BorderLayout.EAST);
            fields.add(selectedDetails);
            var hints = new JPanel(new GridLayout(0, 1, 0, 2));
            hints.add(identifierSample);
            hints.add(cookieSource);
            fields.add(hints);
        }
        var form = Dialogs.stack(7, fields.toArray(JComponent[]::new));
        var heading = Dialogs.heading("Session labeling", anchor == null
                ? "Define a login rule, then preview the labels." : "Choose the identifier and cookie from the selected exchange.");
        var formScroll = new JScrollPane(Dialogs.stack(12, heading, form),
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        formScroll.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 4));
        formScroll.getVerticalScrollBar().setUnitIncrement(16);
        var workspace = new JSplitPane(JSplitPane.VERTICAL_SPLIT, formScroll, new JPanel());
        workspace.setResizeWeight(.66);
        root.add(workspace, BorderLayout.CENTER);
        var table = new JTable(sample);
        table.setFillsViewportHeight(true);
        Dialogs.usePlainTableText(table);
        table.getColumnModel().getColumn(0).setPreferredWidth(430);
        var samplePane = new JScrollPane(table);
        samplePane.setPreferredSize(new Dimension(630, 140));
        samplePane.setBorder(BorderFactory.createTitledBorder("Preview · First 50 new notes"));
        if (anchor != null) {
            details.addTab("Selected login exchange", anchorView.component());
            details.addTab("Proposed notes", samplePane);
            workspace.setBottomComponent(details);
        } else {
            workspace.setBottomComponent(samplePane);
        }
        start.setToolTipText("Enter an exact path such as /login or a regex such as ^/login$.");
        cookie.setToolTipText("Enter the cookie name, such as session_id.");
        live.setToolTipText("Save the rule to apply it to new Proxy records.");

        JPanel footer = new JPanel(new BorderLayout(0, 6));
        JPanel feedback = new JPanel(new BorderLayout(8, 0));
        progress.setPreferredSize(new Dimension(100, 16));
        feedback.add(status);
        feedback.add(progress, BorderLayout.EAST);
        footer.add(feedback, BorderLayout.NORTH);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.TRAILING, 4, 0));
        for (var button : List.of(cancel, close, save, preview, apply)) buttons.add(button);
        footer.add(buttons, BorderLayout.SOUTH);
        root.add(footer, BorderLayout.SOUTH);

        preview.addActionListener(event -> preview());
        reloadAnchor.addActionListener(event -> suggest());
        apply.addActionListener(event -> apply());
        save.addActionListener(event -> save());
        cancel.addActionListener(event -> stop());
        close.addActionListener(event -> dispose());
        apply.setEnabled(false);
        cancel.setEnabled(false);
        getRootPane().setDefaultButton(preview);
        getRootPane().registerKeyboardAction(event -> {
            if (cancel.isEnabled()) stop();
            else if (task == null) dispose();
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

        var invalidation = new DocumentListener() {
            public void insertUpdate(DocumentEvent event) { edited(); }
            public void removeUpdate(DocumentEvent event) { edited(); }
            public void changedUpdate(DocumentEvent event) { edited(); }

            private void edited() {
                invalidatePlan();
                if (!loadingOptions) refreshHints();
            }
        };
        for (var input : List.of(host, method, start,
                (JTextComponent) field.getEditor().getEditorComponent(),
                (JTextComponent) cookie.getEditor().getEditorComponent())) {
            input.getDocument().addDocumentListener(invalidation);
        }
        logout.onEdit(invalidation);
        source.addActionListener(event -> {
            invalidatePlan();
            if (!loadingOptions && suggestions != null) updateFieldChoices(value(field), true);
            refreshHints();
        });
        onlySelected.addActionListener(event -> invalidatePlan());
        scope.addActionListener(event -> invalidatePlan());
        live.addActionListener(event -> invalidatePlan());
        api.userInterface().applyThemeToComponent(root);
        setContentPane(root);
        pack();
        setMinimumSize(new Dimension(750, 520));
        setSize(anchor == null ? 790 : 850, anchor == null ? 540 : 690);
        SwingUtilities.invokeLater(() -> workspace.setDividerLocation(anchor == null ? .63 : .65));
        setLocationRelativeTo(getOwner());
    }

    private void invalidatePlan() {
        if (plan != null) {
            plan = null;
            sample.setRowCount(0);
            apply.setEnabled(false);
            status.setText("The rule changed. Preview again.");
        }
    }

    private void suggest() {
        invalidatePlan();
        selectedStatus.setText("Opening the selected exchange…");
        boolean firstRead = suggestions == null;
        work("Reading the selected request and response…", true, progress -> {
            var resolved = anchor.resolve(api.proxy().history(), () -> Thread.currentThread().isInterrupted());
            return new SelectionInfo(resolved, SessionSuggestions.read(resolved.exchange()));
        }, info -> {
            suggestions = info.suggestions();
            var resolved = info.resolved();
            var exchange = resolved.exchange();
            anchorView.show(exchange);
            if (firstRead && resolved.item() != null) {
                host.setText(exchange.request().httpService().host());
                method.setText(exchange.request().method());
                start.setText(exchange.request().pathWithoutQuery());
            }
            selectedStatus.setText(resolved.item() != null ? "Selected exchange loaded. Review both messages below."
                    : resolved.ambiguous() ? "Several history rows share this exchange. Preview by login route if appropriate."
                    : "Exact history row unavailable. Preview by login route if appropriate.");
            onlySelected.setToolTipText("Clear this option to preview every login that matches the route.");
            status.setText("Choose the identifier source and cookie, then select Preview.");
            String preferredField = value(field);
            var preferredSide = anchor.editorSide();
            String selectedField = firstRead ? suggestions.matchingField(preferredSide, anchor.selection()) : "";
            var choice = (CaptureProfile.Source) source.getSelectedItem();
            if (!selectedField.isEmpty()) {
                preferredField = selectedField;
                choice = preferredSide;
            } else if (!preferredField.isEmpty()) {
                boolean request = suggestions.fields(CaptureProfile.Source.REQUEST).contains(preferredField);
                boolean response = suggestions.fields(CaptureProfile.Source.RESPONSE).contains(preferredField);
                if (request != response) choice = request ? CaptureProfile.Source.REQUEST : CaptureProfile.Source.RESPONSE;
            } else if (preferredSide != null && !suggestions.recommendField(preferredSide).isEmpty()) {
                choice = preferredSide;
            } else if (!suggestions.recommendField(CaptureProfile.Source.RESPONSE).isEmpty()) {
                choice = CaptureProfile.Source.RESPONSE;
            } else if (!suggestions.recommendField(CaptureProfile.Source.REQUEST).isEmpty() || !suggestions.hasResponse()) {
                choice = CaptureProfile.Source.REQUEST;
            }

            loadingOptions = true;
            try {
                source.setSelectedItem(choice);
                String initialCookie = value(cookie);
                var names = suggestions.cookies();
                cookie.setModel(new DefaultComboBoxModel<>(names.toArray(String[]::new)));
                setValue(cookie, names.contains(initialCookie) ? initialCookie : suggestions.recommendCookie());
            } finally {
                loadingOptions = false;
            }
            updateFieldChoices(preferredField, false);
        });
    }

    private void updateFieldChoices(String previous, boolean keepManual) {
        var side = (CaptureProfile.Source) source.getSelectedItem();
        var choices = suggestions.fields(side);
        loadingOptions = true;
        try {
            field.setModel(new DefaultComboBoxModel<>(choices.toArray(String[]::new)));
            String next = choices.contains(previous) || !suggestions.value(side, previous).isEmpty() || keepManual && choices.isEmpty()
                    ? previous : suggestions.recommendField(side);
            setValue(field, next);
        } finally {
            loadingOptions = false;
        }
        refreshHints();
    }

    private void refreshHints() {
        if (suggestions == null) return;
        var side = (CaptureProfile.Source) source.getSelectedItem();
        String name = value(field);
        String identifier = suggestions.value(side, name);
        if (side == CaptureProfile.Source.RESPONSE && !suggestions.hasResponse()) {
            identifierSample.setText("Identifier preview: there is no response for the selected exchange.");
        } else if (name.isEmpty()) {
            identifierSample.setText("Identifier preview: choose a field from the selected side.");
        } else if (identifier.isEmpty()) {
            identifierSample.setText("Identifier preview: no unique value on the selected side.");
        } else {
            identifierSample.setText("Identifier preview: " + (identifier.length() > 78
                    ? identifier.substring(0, 78) + "…" : identifier));
        }
        cookieSource.setText("Cookie: " + suggestions.cookieLocation(value(cookie)));
    }

    private record SelectionInfo(SessionAnchor.Resolved resolved, SessionSuggestions suggestions) {}

    private CaptureProfile rule() {
        String login = start.getText().strip();
        String userField = value(field);
        String cookieName = value(cookie);
        if (login.isEmpty() || userField.isEmpty() || cookieName.isEmpty()) {
            throw new IllegalArgumentException("Enter the login path, user identifier field, and session cookie name.");
        }
        if (!scope.isSelected() && host.getText().isBlank()) {
            throw new IllegalArgumentException("Enter a host or use Burp scope.");
        }
        var base = profile.get();
        var rule = new CaptureProfile(base.collect(), base.persistArchive(), scope.isSelected(), host.getText().strip(),
                base.path(), live.isSelected(), (CaptureProfile.Source) source.getSelectedItem(),
                CaptureProfile.Locator.FIELD, userField, base.notePrefix(), cookieName, logout.read(HistoryLabelDialog::pathRule),
                pathRule(login), method.getText().strip().toUpperCase(Locale.ROOT), base.identityRequestBody(),
                base.successfulOnly(), base.sessionMinutes(), base.captureTools());
        rule.compile();
        return rule;
    }

    private void preview() {
        try {
            var rule = rule().compile();
            boolean selectedOnly = anchor != null && onlySelected.isSelected();
            plan = null;
            sample.setRowCount(0);
            work("Scanning Proxy history in chronological order…", true,
                    update -> {
                        var history = api.proxy().history();
                        java.util.function.BooleanSupplier stopped = () -> Thread.currentThread().isInterrupted();
                        if (!selectedOnly) return HistoryLabeler.plan(history, rule, stopped, update);
                        var chosen = anchor.resolve(history, stopped).item();
                        if (chosen == null) {
                            throw new IllegalArgumentException("The exact Proxy history row could not be identified.");
                        }
                        var request = ProxyMessages.request(chosen);
                        if (!rule.covers(request) || !rule.canIdentify(request, Util.MAX_BODY_BYTES)) {
                            throw new IllegalArgumentException("The selected exchange does not match the current login rule.");
                        }
                        return HistoryLabeler.plan(history, rule, chosen, stopped, update);
                    },
                    result -> {
                        plan = result;
                        if (anchor != null) details.setSelectedIndex(1);
                        for (var item : result.sample()) {
                            sample.addRow(new Object[]{item.url(), item.label()});
                        }
                        status.setText(result.scanned() + " records · " + result.distinctUsers() + " users · "
                                + result.changes().size() + " new notes · " + existingNotes(result.existing(), result.conflicts())
                                + (result.undated() == 0 ? "" : " · " + result.undated() + " without timestamps skipped")
                                + (result.limited() ? " · First 25,000 new notes" : ""));
                    });
        } catch (IllegalArgumentException ex) {
            status.setText(ex.getMessage());
        }
    }

    private void apply() {
        var current = plan;
        if (current == null || current.changes().isEmpty()) return;
        try {
            if (!rule().equals(current.profile())) {
                invalidatePlan();
                return;
            }
        } catch (IllegalArgumentException ex) {
            invalidatePlan();
            status.setText(ex.getMessage());
            return;
        }
        work("Adding notes to Proxy history…", false,
                update -> HistoryLabeler.apply(current, () -> Thread.currentThread().isInterrupted(), update),
                result -> {
                    if (result.failed() == 0) {
                        plan = null;
                        sample.setRowCount(0);
                    }
                    status.setText(result.added() + " notes added · "
                            + existingNotes(current.existing() + result.existing(), current.conflicts() + result.conflicts())
                            + (result.failed() == 0 ? "" : " · " + result.failed() + " failed. Select Apply notes to retry.")
                            + (result.failed() == 0 && current.limited() ? " · Preview again for the remaining records." : ""));
                });
    }

    private static String existingNotes(int existing, int conflicts) {
        return existing + " existing labels kept" + (conflicts == 0 ? "" : " (" + conflicts + " differ from this rule)");
    }

    private void save() {
        try {
            var rule = rule();
            work("Saving session rule…", false, update -> {
                saveProfile.save(rule);
                return rule;
            }, saved -> status.setText("Session rule saved to this Burp project."));
        } catch (IllegalArgumentException ex) {
            status.setText(ex.getMessage());
        }
    }

    private <T> void work(String message, boolean stoppable, Operation<T> job, Consumer<T> finish) {
        if (task != null) return;
        setEditable(false);
        cancel.setEnabled(stoppable);
        progress.setIndeterminate(true);
        status.setText(message);
        var worker = new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return job.run(this::setProgress); }
            @Override protected void done() {
                if (task != this) return;
                task = null;
                try {
                    finish.accept(get());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    status.setText("Operation stopped.");
                } catch (ExecutionException ex) {
                    if (ex.getCause() instanceof IllegalArgumentException validation) {
                        status.setText(validation.getMessage());
                    } else {
                        status.setText("The operation failed. See the extension error log.");
                        api.logging().logToError("Session scan failed.", ex.getCause());
                    }
                } finally {
                    setEditable(true);
                    progress.setIndeterminate(false);
                    progress.setValue(0);
                    cancel.setEnabled(false);
                }
            }
        };
        task = worker;
        worker.addPropertyChangeListener(event -> {
            if (task == worker && "progress".equals(event.getPropertyName())) {
                progress.setIndeterminate(false);
                progress.setValue((Integer) event.getNewValue());
            }
        });
        if (!scans.submit(worker)) {
            task = null;
            setEditable(true);
            cancel.setEnabled(false);
            progress.setIndeterminate(false);
            status.setText("The scan queue is full. Stop a scan and try again.");
        }
    }

    private void setEditable(boolean enabled) {
        editable = enabled;
        for (var component : List.of(host, scope, method, start, source, field, cookie, live, onlySelected, reloadAnchor, preview, save, close)) {
            component.setEnabled(enabled);
        }
        logout.setEditable(enabled);
        apply.setEnabled(enabled && plan != null && !plan.changes().isEmpty());
    }

    private void stop() {
        if (task == null || !cancel.isEnabled()) return;
        SwingWorker<?, Void> current = task;
        task = null;
        scans.cancel(current);
        setEditable(true);
        progress.setIndeterminate(false);
        progress.setValue(0);
        cancel.setEnabled(false);
        status.setText("Scan stopped.");
    }

    @Override public void dispose() {
        if (!editable && task != null && !cancel.isEnabled() && isDisplayable()) return;
        stop();
        super.dispose();
    }

    void closeOnUnload() {
        var worker = task;
        task = null;
        if (worker != null) scans.cancel(worker);
        super.dispose();
    }

    private static String pathRule(String path) {
        return path.startsWith("/") ? "^" + Pattern.quote(path) + "$" : path;
    }

    private static String value(JComboBox<String> box) {
        Object item = box.getEditor().getItem();
        return item == null ? "" : item.toString().strip();
    }

    private static void setValue(JComboBox<String> box, String value) {
        box.setSelectedItem(value);
        box.getEditor().setItem(value);
    }


    @FunctionalInterface
    private interface Operation<T> {
        T run(java.util.function.IntConsumer progress) throws Exception;
    }
}
