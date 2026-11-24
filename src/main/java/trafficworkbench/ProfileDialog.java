package trafficworkbench;

import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

final class ProfileDialog extends JDialog {
    @FunctionalInterface
    interface SaveProfile {
        void save(CaptureProfile profile) throws IOException;
    }

    private final JCheckBox successfulOnly = new JCheckBox("Archive only HTTP 2xx and 3xx responses");
    private final JTextField identityPath = new JTextField(28);
    private final JTextField identityMethod = new JTextField(10);
    private final JTextField identityRequestBody = new JTextField(28);
    private final JSpinner sessionMinutes = new JSpinner(new SpinnerNumberModel(30, 0, 1440, 5));
    private final SourcePicker captureTools = new SourcePicker("Capture tools", TrafficSource.capturedSources(), java.util.Set.of());
    private final JCheckBox collect = new JCheckBox("Archive Proxy traffic");
    private final JCheckBox persist = new JCheckBox("Save archive to Burp project");
    private final JCheckBox scope = new JCheckBox("Include requests in Burp target scope only");
    private final JTextField hosts = new JTextField(30);
    private final JTextField path = new JTextField(30);
    private final JCheckBox annotate = new JCheckBox("Add user notes to Proxy history");
    private final JComboBox<CaptureProfile.Source> source = new JComboBox<>(CaptureProfile.Source.values());
    private final JComboBox<CaptureProfile.Locator> locator = new JComboBox<>(CaptureProfile.Locator.values());
    private final JTextField expression = new JTextField(28);
    private final JTextField prefix = new JTextField(28);
    private final JTextField cookie = new JTextField(28);
    private final LogoutFields logout = new LogoutFields(false);
    private final JLabel status = new JLabel(" ");
    private final JButton save = new JButton("Save to project");
    private final JButton importButton = new JButton("Import profile…");
    private final JButton exportButton = new JButton("Export profile…");
    private final JButton test = new JButton("Test with body…");
    private final JButton close = new JButton("Close");
    private final SaveProfile apply;
    private final Logging logging;
    private CaptureProfile saved;
    private boolean busy;
    private boolean closing;
    private SwingWorker<?, ?> operation;

    ProfileDialog(Window owner, CaptureProfile initial, SaveProfile apply, Logging logging) {
        super(owner, "HTTP Traffic Workbench · Project settings", ModalityType.DOCUMENT_MODAL);
        this.apply = apply;
        this.logging = logging;
        saved = initial;
        setProfile(initial);
        build();
    }

    private void build() {
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosing(java.awt.event.WindowEvent event) { close(); }
        });
        JPanel root = new JPanel(new BorderLayout(0, 14));
        root.setBorder(BorderFactory.createEmptyBorder(18, 20, 16, 20));
        root.add(Dialogs.heading("Project settings", "Set up capture, storage, and user labeling."), BorderLayout.NORTH);

        JPanel groups = new JPanel(new GridBagLayout());
        addGroup(groups, group("Capture and storage",
                collect, row("Other Burp tools", captureTools), persist, successfulOnly, scope, row("Hostnames", hosts), row("Request path regex", path)), 0);
        addGroup(groups, group("User identifier",
                annotate, row("Source priority", source), row("Extraction method", locator),
                row("Field, header, or regex", expression), row("Extraction path regex", identityPath),
                row("Extraction HTTP method", identityMethod), row("Login request body regex", identityRequestBody),
                row("Note prefix", prefix)), 1);
        addGroup(groups, group("Session matching",
                row("Session cookie", cookie), row("Idle timeout (minutes)", sessionMinutes)), 2);
        addGroup(groups, group("Logout", logout.rows("Logout response body regex", true).toArray(JComponent[]::new)), 3);
        var scroll = new JScrollPane(groups);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        root.add(scroll, BorderLayout.CENTER);

        hosts.setToolTipText("Comma-separated hostnames, such as app.example.test, api.example.test");
        path.setToolTipText("Leave blank for all paths. Use ^/api/ to match a path prefix.");
        persist.setToolTipText("Save raw request and response samples in the current Burp project file.");
        expression.setToolTipText("Enter a value such as userId. A regex uses the first capture group.");
        cookie.setToolTipText("Enter a cookie name such as session_id. Leave blank to label each message independently.");
        identityMethod.setToolTipText("Enter an HTTP method such as POST. Leave blank for all methods.");
        identityPath.setToolTipText("Enter a path pattern such as ^/login$. Leave blank to search every matching path.");
        identityRequestBody.setToolTipText("Optional regex to identify the login operation on a shared route.");
        sessionMinutes.setToolTipText("The default is 30 minutes. Enter 0 for no timeout.");
        locator.addActionListener(event -> expression.setToolTipText(
                switch ((CaptureProfile.Locator) locator.getSelectedItem()) {
                    case FIELD -> "Enter a case-sensitive field name such as userId.";
                    case HEADER -> "Enter an HTTP header such as X-User-Id.";
                    case REGEX -> "Capture the identifier in the first group, as in user-id=(\\w+)";
                }));

        JPanel footer = new JPanel(new BorderLayout(0, 6));
        footer.add(status, BorderLayout.NORTH);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.TRAILING, 5, 0));
        for (var button : List.of(importButton, exportButton, test, close, save)) actions.add(button);
        footer.add(actions, BorderLayout.SOUTH);
        root.add(footer, BorderLayout.SOUTH);

        save.addActionListener(event -> save());
        importButton.addActionListener(event -> transfer(true));
        exportButton.addActionListener(event -> transfer(false));
        test.addActionListener(event -> test());
        close.addActionListener(event -> close());
        getRootPane().setDefaultButton(save);
        getRootPane().registerKeyboardAction(event -> close(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        setContentPane(root);
        pack();
        setMinimumSize(new Dimension(665, 460));
        setSize(Math.max(720, getWidth()), Math.min(680, getHeight()));
        setLocationRelativeTo(getOwner());
    }

    private static JPanel group(String title, JComponent... fields) {
        var panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(3, 5, 6, 5)));
        var constraints = new GridBagConstraints();
        constraints.weightx = 1;
        constraints.gridx = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(3, 9, 3, 9);
        for (int i = 0; i < fields.length; i++) {
            constraints.gridy = i;
            panel.add(fields[i], constraints);
        }
        return panel;
    }

    private static void addGroup(JPanel groups, JPanel group, int position) {
        var constraints = new GridBagConstraints();
        constraints.gridy = position;
        constraints.weightx = 1;
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(0, 0, 10, 2);
        groups.add(group, constraints);
    }

    private static JPanel row(String title, JComponent field) {
        return Dialogs.alignedField(title, field, "Login request body regex");
    }

    private void save() {
        if (busy) return;
        try {
            sessionMinutes.commitEdit();
            CaptureProfile profile = read();
            profile.compile();
            if (saved.persistArchive() && !profile.persistArchive()
                    && !Dialogs.confirm(this,
                    "Remove the saved archive from the Burp project? The archive remains available during this session.",
                    "Project archive storage", "Remove saved archive")) {
                return;
            }
            work("Saving…", () -> {
                apply.save(profile);
                return profile;
            }, result -> {
                saved = result;
                status.setText("Profile saved to this Burp project.");
            });
        } catch (java.text.ParseException ex) {
            status.setText("Enter a valid session timeout.");
        } catch (IllegalArgumentException ex) {
            status.setText(ex.getMessage());
        }
    }

    private void transfer(boolean importing) {
        if (busy) return;
        var chooser = Dialogs.fileChooser(importing, "profile");
        if (!importing) chooser.setSelectedFile(new java.io.File("http-traffic-workbench.properties"));
        int result = importing ? chooser.showOpenDialog(this) : chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) return;
        Path file = chooser.getSelectedFile().toPath();
        if (importing) {
            work("Reading profile…", () -> Persistence.importProfile(file), profile -> {
                setProfile(profile);
                status.setText("Profile loaded. Save it to the project to apply the settings.");
            });
        } else if (confirmReplace(file)) {
            try {
                var profile = read();
                profile.compile();
                work("Writing profile…", () -> {
                    Persistence.exportProfile(file, profile);
                    return file;
                }, written -> status.setText("Profile exported."));
            } catch (IllegalArgumentException ex) {
                status.setText(ex.getMessage());
            }
        }
    }

    private boolean confirmReplace(Path file) {
        return !Files.exists(file) || Dialogs.confirm(this,
                "Overwrite " + file.getFileName() + "?", "Overwrite file", "Overwrite");
    }

    private void test() {
        if (busy) return;
        try {
            var compiled = read().compile();
            if (compiled.settings().locator() == CaptureProfile.Locator.HEADER) {
                status.setText("Select Field name or Body regex to test against a message body.");
                return;
            }
            if (compiled.settings().expression().isBlank()) {
                status.setText("Enter a user identifier field or regex first.");
                expression.requestFocusInWindow();
                return;
            }
            JTextArea body = new JTextArea(10, 45);
            JTextField contentType = new JTextField();
            JPanel form = new JPanel(new BorderLayout(0, 6));
            form.add(row("Content-Type", contentType), BorderLayout.NORTH);
            form.add(new JScrollPane(body));
            body.getAccessibleContext().setAccessibleName("Sample body");
            if (!Dialogs.confirm(this, form, "Test identifier extraction", "Test body")) return;
            String sample = body.getText();
            if (sample.length() > 4 * 1024 * 1024) {
                status.setText("The sample body exceeds the size limit.");
                return;
            }
            String type = contentType.getText().strip();
            work("Searching for the identifier…", () -> compiled.identify(new Util.MessageText(sample, type, null,
                            java.nio.charset.StandardCharsets.UTF_8)),
                    label -> status.setText(label.isEmpty() ? "No unique user identifier was found."
                            : "Extracted value · " + label));
        } catch (IllegalArgumentException ex) {
            status.setText(ex.getMessage());
        }
    }

    private <T> void work(String message, Callable<T> task, java.util.function.Consumer<T> success) {
        if (closing) return;
        busy = true;
        status.setText(message);
        for (var button : List.of(save, importButton, exportButton, test, close)) button.setEnabled(false);
        operation = new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return task.call(); }
            @Override protected void done() {
                operation = null;
                if (closing) return;
                busy = false;
                for (var button : List.of(save, importButton, exportButton, test, close)) button.setEnabled(true);
                try {
                    success.accept(get());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    status.setText("Operation interrupted.");
                } catch (ExecutionException ex) {
                    logging.logToError("Project settings operation failed.", ex.getCause());
                    status.setText("The operation failed. " + ex.getCause().getMessage());
                }
            }
        };
        operation.execute();
    }

    void closeOnUnload() {
        closing = true;
        if (operation != null) operation.cancel(true);
        dispose();
    }

    private void close() {
        if (busy) return;
        if (!read().equals(saved) && !Dialogs.confirm(this,
                "Discard unsaved profile changes?", "Unsaved changes", "Discard changes")) return;
        dispose();
    }

    private CaptureProfile read() {
        return new CaptureProfile(collect.isSelected(), persist.isSelected(), scope.isSelected(), hosts.getText().strip(),
                path.getText().strip(), annotate.isSelected(), (CaptureProfile.Source) source.getSelectedItem(),
                (CaptureProfile.Locator) locator.getSelectedItem(), expression.getText().strip(), prefix.getText().strip(),
                cookie.getText().strip(), logout.read(java.util.function.UnaryOperator.identity()), identityPath.getText().strip(),
                identityMethod.getText().strip().toUpperCase(java.util.Locale.ROOT), identityRequestBody.getText().strip(),
                successfulOnly.isSelected(),
                (Integer) sessionMinutes.getValue(), captureTools.selected());
    }

    private void setProfile(CaptureProfile profile) {
        collect.setSelected(profile.collect());
        captureTools.select(profile.captureTools());
        successfulOnly.setSelected(profile.successfulOnly());
        identityPath.setText(profile.identityPath());
        identityMethod.setText(profile.identityMethod());
        identityRequestBody.setText(profile.identityRequestBody());
        sessionMinutes.setValue(profile.sessionMinutes());
        persist.setSelected(profile.persistArchive());
        scope.setSelected(profile.inScope());
        hosts.setText(profile.hosts());
        path.setText(profile.path());
        annotate.setSelected(profile.annotate());
        source.setSelectedItem(profile.source());
        locator.setSelectedItem(profile.locator());
        expression.setText(profile.expression());
        prefix.setText(profile.notePrefix());
        cookie.setText(profile.sessionCookie());
        logout.setRule(profile.logout());
    }
}
