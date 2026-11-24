package trafficworkbench;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.List;
import java.util.Locale;
import java.util.function.UnaryOperator;

final class LogoutFields {
    private static final String DEFAULT_STATUSES = "2xx, 3xx";
    private final JTextField path = new JTextField(25);
    private final JTextField method = new JTextField(8);
    private final JTextField statuses = new JTextField(16);
    private final JTextField request = new JTextField(25);
    private final JTextField response = new JTextField(25);
    private final JLabel bodyConditions = new JLabel("Body conditions are set in Project settings.");
    private final List<JTextField> inputs = List.of(path, method, statuses, request, response);
    private boolean editable = true;

    LogoutFields(boolean exactPathByDefault) {
        path.setToolTipText(exactPathByDefault ? "Enter an exact path such as /logout or a regex such as ^/logout$."
                : "Enter a regex such as ^/logout$. Clear this field to disable the logout rule.");
        method.setToolTipText("Optional HTTP method, such as POST. Blank matches any method.");
        statuses.setToolTipText("Blank accepts HTTP 2xx and 3xx. Enter codes such as 204, 302, or any to skip checking the status.");
        request.setToolTipText("Optional regex for a logout operation on a shared route.");
        response.setToolTipText("Optional regex for a logout success marker in the response body.");
        path.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent event) { updateEnabled(); }
            public void removeUpdate(DocumentEvent event) { updateEnabled(); }
            public void changedUpdate(DocumentEvent event) { updateEnabled(); }
        });
        updateEnabled();
    }

    List<JComponent> rows(String reference, boolean showBodyConditions) {
        var rows = new java.util.ArrayList<JComponent>();
        rows.add(Dialogs.alignedField("Logout path", path, reference));
        rows.add(Dialogs.alignedField("Logout HTTP method", method, reference));
        rows.add(Dialogs.alignedField("Logout HTTP status", statuses, reference));
        if (showBodyConditions) {
            rows.add(Dialogs.alignedField("Logout request body regex", request, reference));
            rows.add(Dialogs.alignedField("Logout response body regex", response, reference));
        } else {
            rows.add(bodyConditions);
        }
        return rows;
    }

    void setRule(LogoutRule rule) {
        path.setText(rule.path());
        method.setText(rule.method());
        statuses.setText(rule.statuses().isEmpty() ? DEFAULT_STATUSES : rule.statuses());
        request.setText(rule.requestBody());
        response.setText(rule.responseBody());
        bodyConditions.setVisible(!rule.requestBody().isEmpty() || !rule.responseBody().isEmpty());
    }

    LogoutRule read(UnaryOperator<String> pathRule) {
        String route = path.getText().strip();
        if (route.isEmpty()) return LogoutRule.NONE;
        String codes = statuses.getText().strip();
        return new LogoutRule(pathRule.apply(route), method.getText().strip().toUpperCase(Locale.ROOT),
                codes.equals(DEFAULT_STATUSES) ? "" : codes, request.getText().strip(), response.getText().strip());
    }

    void onEdit(DocumentListener listener) {
        for (var input : inputs) input.getDocument().addDocumentListener(listener);
    }

    void setEditable(boolean editable) {
        this.editable = editable;
        updateEnabled();
    }

    private void updateEnabled() {
        path.setEnabled(editable);
        boolean active = editable && !path.getText().isBlank();
        for (var input : inputs.subList(1, inputs.size())) input.setEnabled(active);
    }
}
