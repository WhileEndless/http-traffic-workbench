package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;

final class ExchangeView {
    private static final int MAX_PREVIEW_BYTES = 2 * 1024 * 1024;
    private static final int MAX_HIGHLIGHT_BYTES = 1024 * 1024;

    private final HttpRequestEditor request;
    private final HttpResponseEditor response;
    private final CardLayout requestLayout = new CardLayout();
    private final CardLayout responseLayout = new CardLayout();
    private final JPanel requestCards = new JPanel(requestLayout);
    private final JPanel responseCards = new JPanel(responseLayout);
    private final JButton loadRequest = new JButton("Load full request");
    private final JButton loadResponse = new JButton("Load full response");
    private final JLabel requestStatus = new JLabel("Select a record.", SwingConstants.CENTER);
    private final JLabel responseStatus = new JLabel("Select a record.", SwingConstants.CENTER);
    private final JSplitPane split;
    private HttpRequestResponse current;
    private int requestBytes;
    private int responseBytes;
    private String requestSearch = "";
    private String responseSearch = "";

    ExchangeView(MontoyaApi api) {
        request = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        response = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        requestCards.add(request.uiComponent(), "editor");
        requestCards.add(statusCard(requestStatus, loadRequest), "status");
        responseCards.add(response.uiComponent(), "editor");
        responseCards.add(statusCard(responseStatus, loadResponse), "status");
        loadRequest.addActionListener(event -> {
            var exchange = current;
            if (exchange != null && exchange.request() != null) {
                request.setRequest(exchange.request());
                requestLayout.show(requestCards, "editor");
            }
        });
        loadResponse.addActionListener(event -> {
            var exchange = current;
            if (exchange != null && exchange.response() != null) {
                response.setResponse(exchange.response());
                responseLayout.show(responseCards, "editor");
            }
        });
        requestLayout.show(requestCards, "status");
        responseLayout.show(responseCards, "status");
        requestCards.setBorder(BorderFactory.createTitledBorder("Request"));
        responseCards.setBorder(BorderFactory.createTitledBorder("Response"));
        split = split(JSplitPane.HORIZONTAL_SPLIT, requestCards, responseCards, .5);
    }

    private static JPanel statusCard(JLabel status, JButton action) {
        var panel = new JPanel(new GridBagLayout());
        var position = new GridBagConstraints();
        position.gridx = 0;
        position.gridy = 0;
        position.insets = new Insets(4, 6, 4, 6);
        panel.add(status, position);
        position.gridy++;
        action.setVisible(false);
        panel.add(action, position);
        return panel;
    }

    static JSplitPane split(int orientation, Component first, Component second, double ratio) {
        var layout = new JSplitPane(orientation, first, second);
        layout.setResizeWeight(ratio);
        layout.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent event) {
                if (layout.getWidth() <= 0 || layout.getHeight() <= 0) return;
                layout.removeComponentListener(this);
                layout.setDividerLocation(ratio);
            }
        });
        return layout;
    }

    JComponent component() { return split; }

    void show(HttpRequestResponse exchange) {
        show(exchange, "");
    }

    void show(HttpRequestResponse exchange, String search) {
        show(exchange, search, search);
    }

    void show(HttpRequestResponse exchange, String requestMatch, String responseMatch) {
        boolean messageChanged = current != exchange;
        if (messageChanged) {
            current = exchange;
            loadEditors(exchange);
        }
        String requestTerm = requestBytes > 0 && requestBytes <= MAX_HIGHLIGHT_BYTES ? requestMatch : "";
        String responseTerm = responseBytes > 0 && responseBytes <= MAX_HIGHLIGHT_BYTES ? responseMatch : "";
        if (requestBytes > 0 && requestBytes <= MAX_PREVIEW_BYTES
                && (!requestTerm.equals(requestSearch) || messageChanged && !requestTerm.isEmpty())) {
            requestSearch = requestTerm;
            request.setSearchExpression(requestTerm);
        }
        if (responseBytes > 0 && responseBytes <= MAX_PREVIEW_BYTES
                && (!responseTerm.equals(responseSearch) || messageChanged && !responseTerm.isEmpty())) {
            responseSearch = responseTerm;
            response.setSearchExpression(responseTerm);
        }
    }

    private void loadEditors(HttpRequestResponse exchange) {
        var req = exchange == null ? null : exchange.request();
        var res = exchange == null ? null : exchange.response();
        requestBytes = req == null ? 0 : req.toByteArray().length();
        responseBytes = res == null ? 0 : res.toByteArray().length();
        loadRequest.setVisible(req != null && requestBytes > MAX_PREVIEW_BYTES);
        loadResponse.setVisible(res != null && responseBytes > MAX_PREVIEW_BYTES);

        if (req != null && requestBytes <= MAX_PREVIEW_BYTES) {
            request.setRequest(req);
            requestLayout.show(requestCards, "editor");
        } else {
            requestStatus.setText(req == null ? "Select a record." : "The request exceeds the preview limit.");
            requestLayout.show(requestCards, "status");
        }
        if (res != null && responseBytes <= MAX_PREVIEW_BYTES) {
            response.setResponse(res);
            responseLayout.show(responseCards, "editor");
        } else {
            responseStatus.setText(exchange == null ? "Select a record."
                    : res == null ? "No response was recorded for this exchange." : "The response exceeds the preview limit.");
            responseLayout.show(responseCards, "status");
        }
    }
}
