package trafficworkbench;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Dialog;
import java.awt.event.KeyEvent;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.net.URI;

final class BuildInfo {
    static final String OWNER = "WhileEndless";
    static final String REPOSITORY = "http-traffic-workbench";
    static final String OWNER_URL = "https://github.com/" + OWNER;
    static final String REPOSITORY_URL = OWNER_URL + "/" + REPOSITORY;
    private static final String VERSION = version();

    private BuildInfo() {}

    static String release() {
        return "v" + VERSION;
    }

    private static String version() {
        String manifestVersion = BuildInfo.class.getPackage().getImplementationVersion();
        return manifestVersion == null ? "1.0.1" : manifestVersion;
    }

    static void show(Component parent) {
        var window = SwingUtilities.getWindowAncestor(parent);
        var dialog = new JDialog(window, "About HTTP Traffic Workbench", Dialog.ModalityType.DOCUMENT_MODAL);
        dialog.setContentPane(content(dialog::dispose));
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.getRootPane().registerKeyboardAction(event -> dialog.dispose(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        dialog.pack();
        dialog.setResizable(false);
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);
    }

    static JPanel content(Runnable dismiss) {
        var content = new JPanel(new BorderLayout(0, 16));
        content.setBorder(BorderFactory.createEmptyBorder(22, 24, 18, 24));
        content.add(Dialogs.heading(TrafficWorkbench.NAME, "Version " + release()), BorderLayout.NORTH);

        var openRepository = new JButton("Open repository");
        var openProfile = new JButton("Open GitHub profile");
        var copy = new JButton("Copy repository URL");
        var status = new JLabel(" ");
        openRepository.addActionListener(event -> open(REPOSITORY_URL, status));
        openProfile.addActionListener(event -> open(OWNER_URL, status));
        copy.addActionListener(event -> {
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(REPOSITORY_URL), null);
                status.setText("Repository URL copied.");
            } catch (IllegalStateException ex) {
                status.setText("The clipboard is busy.");
            }
        });

        var links = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        links.add(openRepository);
        links.add(openProfile);
        links.add(copy);
        var details = new JPanel(new GridLayout(0, 2, 14, 8));
        details.add(new JLabel("GitHub owner"));
        details.add(new JLabel(OWNER));
        details.add(new JLabel("Repository"));
        details.add(new JLabel(REPOSITORY));
        var project = Dialogs.stack(12, new JSeparator(), details, links);
        content.add(project, BorderLayout.CENTER);

        var footer = new JPanel(new BorderLayout(12, 0));
        var close = new JButton("Close");
        close.addActionListener(event -> dismiss.run());
        footer.add(status, BorderLayout.CENTER);
        footer.add(close, BorderLayout.EAST);
        content.add(footer, BorderLayout.SOUTH);
        return content;
    }

    private static void open(String url, JLabel status) {
        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            status.setText("Browser integration is unavailable. Copy the URL to open it.");
            return;
        }
        status.setText("Opening GitHub…");
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() throws Exception {
                Desktop.getDesktop().browse(URI.create(url));
                return null;
            }

            @Override protected void done() {
                try {
                    get();
                    status.setText(" ");
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    status.setText("Opening GitHub was interrupted.");
                } catch (java.util.concurrent.ExecutionException ex) {
                    status.setText("Could not open GitHub. Copy the URL to open it.");
                }
            }
        }.execute();
    }
}
