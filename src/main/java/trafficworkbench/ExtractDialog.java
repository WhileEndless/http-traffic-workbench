package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.function.Supplier;

final class ExtractDialog extends JDialog {
    enum Dataset {
        ALL, HISTORY, ARCHIVE;

        java.util.Set<TrafficSource> sources() {
            return switch (this) {
                case ALL -> java.util.EnumSet.allOf(TrafficSource.class);
                case HISTORY -> java.util.Set.of(TrafficSource.PROXY);
                case ARCHIVE -> {
                    var selected = java.util.EnumSet.copyOf(TrafficSource.capturedSources());
                    selected.add(TrafficSource.ARCHIVE);
                    yield selected;
                }
            };
        }
    }

    record SelectedExchange(HttpRequestResponse exchange, TrafficSource source) {
        CapturedEntry entry(CaptureProfile profile) {
            return TrafficCatalog.record(exchange, exchange.annotations(), 0, source, 0, profile);
        }
    }

    record Context(String selection, String path, Supplier<List<FieldExtractor.Pair>> fields,
                   CookieTrace cookie, SelectedExchange selectedExchange) {
        Context(String selection, String path, Supplier<List<FieldExtractor.Pair>> fields) {
            this(selection, path, fields, null, null);
        }

        static Context empty() { return new Context("", "", List::of); }
    }

    private final SearchPanel panel;

    ExtractDialog(MontoyaApi api, CollectorStore store, ScanQueue scans, Supplier<CaptureProfile> profile,
                  Dataset initialDataset, Context context) {
        super(api.userInterface().swingUtils().suiteFrame(), "HTTP Traffic Workbench · "
                + (initialDataset == Dataset.ARCHIVE ? "Search archive" : "Search traffic"), false);
        panel = new SearchPanel(api, store, scans, profile, initialDataset, context, this::dispose);
        api.userInterface().applyThemeToComponent(panel);
        setContentPane(panel);
        panel.bindDefaultAction(getRootPane());
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        addWindowFocusListener(new java.awt.event.WindowAdapter() {
            @Override public void windowGainedFocus(java.awt.event.WindowEvent event) {
                panel.windowFocused();
            }
        });
        getRootPane().registerKeyboardAction(event -> dispose(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        setMinimumSize(new Dimension(760, 500));
        setSize(1050, 710);
        setLocationRelativeTo(getOwner());
    }

    void searchSelection() {
        panel.searchSelection();
    }

    @Override public void dispose() {
        if (panel != null) panel.close();
        super.dispose();
    }

    static JPanel labeled(String text, JComponent input) {
        JPanel panel = new JPanel(new BorderLayout(6, 0));
        JLabel label = new JLabel(text);
        label.setLabelFor(input);
        panel.add(label, BorderLayout.WEST);
        panel.add(input);
        return panel;
    }

}
