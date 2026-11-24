package trafficworkbench;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.Component;
import java.util.Arrays;
import java.util.LinkedHashSet;

record CookieTrace(String name, String value, HttpService service, boolean followReplacements) {
    CookieTrace(String name, String value, HttpService service) {
        this(name, value, service, false);
    }

    CookieTrace {
        if (followReplacements && service == null) {
            throw new IllegalArgumentException("Cookie replacement tracking requires one service.");
        }
        if (!Cookies.validName(name)) {
            throw new IllegalArgumentException("Enter a valid HTTP cookie name.");
        }
        if (value.isEmpty() || value.length() > Cookies.MAX_VALUE_CHARS || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Enter a cookie value of up to 4,096 characters.");
        }
    }

    boolean appliesTo(HttpService candidate) {
        return service == null || candidate != null && candidate.host().equalsIgnoreCase(service.host())
                && candidate.port() == service.port() && candidate.secure() == service.secure();
    }

    boolean matches(HttpMessage message, boolean response) {
        boolean[] matched = {false};
        Cookies.read(message, response, name, field -> {
            if (field.value().equals(value)) matched[0] = true;
        });
        return matched[0];
    }

    @Override public String toString() {
        return "Cookie trace · " + name;
    }

    static CookieTrace prompt(Component parent, HttpRequestResponse exchange, CaptureProfile.Source side) {
        var observed = new LinkedHashSet<Cookies.Field>();
        if (exchange != null) {
            if (side == CaptureProfile.Source.RESPONSE) {
                observed.addAll(Cookies.fields(exchange.response(), true));
            }
            observed.addAll(Cookies.fields(exchange.request(), false));
            observed.addAll(Cookies.fields(exchange.response(), true));
        }
        var candidates = observed.stream().filter(field -> !field.value().isEmpty()).limit(200).toArray(Cookies.Field[]::new);
        var choice = new JComboBox<Object>();
        choice.addItem("Enter manually");
        for (var candidate : candidates) choice.addItem(candidate);
        var name = new JTextField(27);
        var value = new JPasswordField(27);
        char masked = value.getEchoChar();
        var reveal = new JToggleButton("Show value");
        reveal.addActionListener(event -> {
            value.setEchoChar(reveal.isSelected() ? (char) 0 : masked);
            reveal.setText(reveal.isSelected() ? "Hide value" : "Show value");
        });
        var sameService = new JCheckBox("Limit to this host, port, and protocol", exchange != null);
        var follow = new JCheckBox("Follow observed replacements in Proxy history");
        follow.setVisible(exchange != null);
        sameService.addActionListener(event -> {
            follow.setEnabled(sameService.isSelected());
            if (!sameService.isSelected()) follow.setSelected(false);
        });
        sameService.setVisible(exchange != null);
        choice.addActionListener(event -> {
            if (choice.getSelectedItem() instanceof Cookies.Field field) {
                name.setText(field.name());
                value.setText(field.value());
            } else {
                name.setText("");
                value.setText("");
            }
        });
        if (candidates.length > 0) choice.setSelectedIndex(1);
        var fields = new java.util.ArrayList<JComponent>();
        if (candidates.length > 0) fields.add(Dialogs.alignedField("Observed cookie", choice, "Observed cookie"));
        fields.add(Dialogs.alignedField("Cookie name", name, "Observed cookie"));
        var valueRow = new JPanel(new java.awt.BorderLayout(6, 0));
        valueRow.add(Dialogs.alignedField("Cookie value", value, "Observed cookie"), java.awt.BorderLayout.CENTER);
        valueRow.add(reveal, java.awt.BorderLayout.EAST);
        fields.add(valueRow);
        if (exchange != null) {
            fields.add(sameService);
            fields.add(follow);
        }
        JLabel status = new JLabel("Matches inspect Cookie and Set-Cookie headers in the selected sources.");
        fields.add(status);
        var form = Dialogs.stack(11, fields.toArray(JComponent[]::new));
        form.setBorder(BorderFactory.createEmptyBorder(7, 4, 8, 4));
        follow.addActionListener(event -> status.setText(follow.isSelected()
                ? "Uses chronological Proxy history and stops when the tracked cookie is removed."
                : "Matches inspect Cookie and Set-Cookie headers in the selected sources."));
        while (Dialogs.confirm(parent, form, "Trace a cookie", "Trace cookie")) {
            char[] chars = value.getPassword();
            try {
                HttpService service = sameService.isSelected() && exchange != null ? exchange.request().httpService() : null;
                return new CookieTrace(name.getText().strip(), new String(chars), service, follow.isSelected());
            } catch (IllegalArgumentException ex) {
                status.setText(ex.getMessage());
            } finally {
                Arrays.fill(chars, '\0');
            }
        }
        return null;
    }
}
