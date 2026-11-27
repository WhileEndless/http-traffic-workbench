package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.awt.Container;
import java.awt.KeyboardFocusManager;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

final class SearchContextMenu implements ContextMenuItemsProvider {
    private static final int SELECTION_LIMIT = 8192;

    private final MontoyaApi api;
    private final CollectorStore store;
    private final Supplier<CaptureProfile> profile;
    private final ProfileDialog.SaveProfile saveProfile;
    private final Set<HistoryLabelDialog> historyDialogs = new HashSet<>();
    private final ScanQueue scans = new ScanQueue();
    private final Set<ExtractDialog> dialogs = new HashSet<>();
    private volatile boolean closed;

    SearchContextMenu(MontoyaApi api, CollectorStore store, Supplier<CaptureProfile> profile, ProfileDialog.SaveProfile saveProfile) {
        this.api = api;
        this.store = store;
        this.profile = profile;
        this.saveProfile = saveProfile;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        var editor = event.messageEditorRequestResponse().orElse(null);
        List<HttpRequestResponse> messages = event.selectedRequestResponses();
        HttpRequestResponse anchor;
        String selection = "";
        CaptureProfile.Source anchorSide = null;
        String path = "";
        Supplier<List<FieldExtractor.Pair>> source = List::of;
        if (editor != null) {
            var exchange = editor.requestResponse();
            anchor = exchange;
            boolean request = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
            anchorSide = request ? CaptureProfile.Source.REQUEST : CaptureProfile.Source.RESPONSE;
            var message = request ? exchange.request() : exchange.response();
            if (exchange.request() != null && exchange.request().httpService() != null) {
                path = CapturedEntry.endpoint(exchange.request());
            }
            source = () -> HttpSearchFields.collect(exchange, request);
            selection = editorSelection(event.inputEvent(), message, editor.selectionOffsets().orElse(null));
        } else if (!messages.isEmpty()) {
            var exchange = messages.get(0);
            anchor = exchange;
            if (exchange.request() != null && exchange.request().httpService() != null) {
                path = CapturedEntry.endpoint(exchange.request());
            }
            source = () -> {
                var fields = new ArrayList<>(HttpSearchFields.collect(exchange, true));
                fields.addAll(HttpSearchFields.collect(exchange, false));
                return fields;
            };
        } else {
            return List.of();
        }
        var tool = event.toolType();
        var origin = tool == ToolType.PROXY ? TrafficSource.PROXY
                : tool == ToolType.LOGGER ? TrafficSource.ARCHIVE : TrafficSource.forTool(tool);
        var selectedExchange = anchor == null ? null : new ExtractDialog.SelectedExchange(anchor, origin);
        var context = new ExtractDialog.Context(selection, path, source, null, selectedExchange, anchorSide);
        JMenuItem menu = new JMenuItem(selection.isEmpty()
                ? "HTTP Traffic Workbench · Search traffic…" : "HTTP Traffic Workbench · Search traffic for selection…");
        menu.addActionListener(eventClick -> open(ExtractDialog.Dataset.ALL, context));
        var items = new ArrayList<Component>();
        items.add(menu);
        if ((editor != null || messages.size() == 1) && anchor != null && anchor.request() != null && anchor.request().httpService() != null) {
            var chosen = new SessionAnchor(anchor, anchorSide, selection);
            JMenuItem settings = new JMenuItem("HTTP Traffic Workbench · Use selected exchange as login…");
            settings.addActionListener(click -> openHistoryLabeler(chosen));
            items.add(settings);
        }
        if ((editor != null || messages.size() == 1) && anchor != null && anchor.request() != null) {
            var side = anchorSide;
            var trace = new JMenuItem("HTTP Traffic Workbench · Trace a cookie…");
            trace.addActionListener(click -> openCookieTrace(anchor, side));
            items.add(trace);
        }
        if (tool == ToolType.LOGGER || origin.toolTraffic()) {
            List<HttpRequestResponse> selected = messages.isEmpty() && anchor != null ? List.of(anchor) : messages;
            JMenuItem add = new JMenuItem(selected.size() == 1 ? "HTTP Traffic Workbench · Archive this exchange"
                    : "HTTP Traffic Workbench · Archive selected exchanges");
            add.setToolTipText("Save the full request and response for later searches in the extension archive.");
            add.addActionListener(click -> archive(selected, List.of(), origin));
            items.add(add);
        }
        return items;
    }

    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        var issues = event.selectedIssues();
        if (issues.isEmpty()) return List.of();
        var search = new JMenuItem("HTTP Traffic Workbench · Search traffic…");
        search.addActionListener(click -> open(ExtractDialog.Dataset.ALL, ExtractDialog.Context.empty()));
        var add = new JMenuItem("HTTP Traffic Workbench · Add issue evidence to archive");
        add.addActionListener(click -> archive(List.of(), issues, TrafficSource.ARCHIVE));
        return List.of(search, add);
    }

    private void archive(List<HttpRequestResponse> selected,
                         List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues, TrafficSource origin) {
        var currentProfile = profile.get();
        var worker = new javax.swing.SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() {
                long time = System.currentTimeMillis();
                var evidence = issues.stream().flatMap(issue -> issue.requestResponses().stream());
                var records = java.util.stream.Stream.concat(selected.stream(), evidence)
                        .filter(java.util.Objects::nonNull)
                        .limit(2_000)
                        .map(exchange -> TrafficCatalog.record(exchange, exchange.annotations(), time, origin, 0, currentProfile))
                        .filter(java.util.Objects::nonNull).toList();
                int accepted = store.addAll(records);
                api.logging().logToOutput(accepted + " selected messages added to the traffic archive.");
                return null;
            }

            @Override protected void done() {
                if (closed || isCancelled()) return;
                try {
                    get();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } catch (java.util.concurrent.ExecutionException ex) {
                    api.logging().logToError("Could not archive the selected messages.", ex.getCause());
                }
            }
        };
        if (!scans.submit(worker)) api.logging().logToError("The scan queue is full. Try adding the selection again.");
    }

    void openCookieTrace(HttpRequestResponse exchange, CaptureProfile.Source side) {
        if (closed) return;
        var trace = CookieTrace.prompt(api.userInterface().swingUtils().suiteFrame(), exchange, side);
        if (trace != null) {
            open(trace.followReplacements() ? ExtractDialog.Dataset.HISTORY : ExtractDialog.Dataset.ALL,
                    new ExtractDialog.Context("", "", List::of, trace, null));
        }
    }

    void openHistoryLabeler(SessionAnchor anchor) {
        if (closed) return;
        var dialog = new HistoryLabelDialog(api, scans, profile, saveProfile, anchor);
        historyDialogs.add(dialog);
        dialog.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent event) { historyDialogs.remove(dialog); }
        });
        dialog.setVisible(true);
    }

    void open(ExtractDialog.Dataset dataset, ExtractDialog.Context context) {
        if (closed) {
            return;
        }
        var dialog = new ExtractDialog(api, store, scans, profile, dataset, context);
        dialogs.add(dialog);
        dialog.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent event) { dialogs.remove(dialog); }
        });
        dialog.setVisible(true);
        dialog.searchSelection();
    }

    void close() {
        closed = true;
        SwingUtilities.invokeLater(() -> {
            new ArrayList<>(dialogs).forEach(ExtractDialog::dispose);
            new ArrayList<>(historyDialogs).forEach(HistoryLabelDialog::closeOnUnload);
            scans.close();
        });
    }

    static String editorSelection(InputEvent event, HttpMessage message, Range range) {
        // Pretty views can report positions in displayed text, which do not index the raw HTTP bytes.
        var editor = textEditor(event);
        if (editor != null) {
            int length = editor.getSelectionEnd() - editor.getSelectionStart();
            if (length <= 0 || length > SELECTION_LIMIT) return "";
            String selected = editor.getSelectedText();
            return selected == null ? "" : clean(selected);
        }
        if (message == null || range == null) return "";
        int start = range.startIndexInclusive();
        int end = range.endIndexExclusive();
        if (start < 0 || end <= start || end - start > SELECTION_LIMIT) return "";
        var bytes = message.toByteArray();
        return end > bytes.length() ? ""
                : clean(new String(bytes.subArray(start, end).getBytes(), StandardCharsets.UTF_8));
    }

    private static JTextComponent textEditor(InputEvent event) {
        if (event == null) return null;
        Component source = event.getComponent();
        if (source instanceof JTextComponent text) return text;
        if (!(source instanceof Container container)) return null;
        if (event instanceof MouseEvent mouse) {
            var clicked = SwingUtilities.getDeepestComponentAt(container, mouse.getX(), mouse.getY());
            return clicked instanceof JTextComponent text ? text : null;
        }
        var focused = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        return focused instanceof JTextComponent text && SwingUtilities.isDescendingFrom(text, container) ? text : null;
    }

    private static String clean(String selection) {
        String text = selection.strip();
        if ((text.startsWith("\"") || text.startsWith("'")) && text.endsWith(":")) {
            text = text.substring(0, text.length() - 1).stripTrailing();
        }
        if (text.length() > 1 && (text.startsWith("\"") && text.endsWith("\"")
                || text.startsWith("'") && text.endsWith("'"))) {
            return text.substring(1, text.length() - 1);
        }
        return text;
    }
}
