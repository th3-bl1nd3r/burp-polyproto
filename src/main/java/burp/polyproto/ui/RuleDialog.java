package burp.polyproto.ui;

import burp.polyproto.core.Direction;
import burp.polyproto.rule.Action;
import burp.polyproto.rule.LabelSpec;
import burp.polyproto.rule.Match;
import burp.polyproto.rule.Rule;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;

/**
 * A modal form for the common rule fields. Advanced fields (transport, anyOf, rewriteHeader,
 * recomputeSig, label pattern/template, ...) are carried over untouched from the source rule so the
 * dialog never silently drops them; use the JSON tab to edit those. Returns a fresh {@link Rule} on
 * OK, or {@code null} on cancel — the source rule is never mutated.
 */
public final class RuleDialog {

    private RuleDialog() {}

    public static Rule edit(Component parent, Rule in) {
        JTextField id = new JTextField(in.id == null ? "" : in.id, 28);
        JTextField name = new JTextField(in.name == null ? "" : in.name, 28);
        JCheckBox enabled = new JCheckBox("enabled", in.enabled);
        JTextField priority = new JTextField(String.valueOf(in.priority), 28);
        JComboBox<Direction> direction = new JComboBox<>(Direction.values());
        direction.setSelectedItem(in.direction == null ? Direction.BOTH : in.direction);

        Match m = in.match;
        JTextField hostsAny = new JTextField(m == null ? "" : join(m.hostsAny), 28);
        JTextField pathRegex = new JTextField(m == null || m.pathRegex == null ? "" : m.pathRegex, 28);
        JTextField methods = new JTextField(m == null ? "" : join(m.methods), 28);
        JTextField contentTypesAny = new JTextField(m == null ? "" : join(m.contentTypesAny), 28);

        Action a = in.action;
        JTextField forcePipeline = new JTextField(a == null ? "" : join(a.forcePipeline), 28);
        JTextField schemaPack = new JTextField(a == null || a.schemaPack == null ? "" : a.schemaPack, 28);
        JTextField encodingHeaders = new JTextField(a == null ? "" : join(a.encodingHeaders), 28);
        LabelSpec lin = a == null ? null : a.label;
        JTextField labelFrom = new JTextField(lin == null || lin.from == null ? "" : lin.from, 28);
        JTextField labelKey = new JTextField(lin == null || lin.key == null ? "" : lin.key, 28);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(2, 4, 2, 4);
        int row = 0;
        addRow(form, c, row++, "id", id);
        addRow(form, c, row++, "name", name);
        addRow(form, c, row++, "", enabled);
        addRow(form, c, row++, "priority", priority);
        addRow(form, c, row++, "direction", direction);
        addRow(form, c, row++, "match.hostsAny", hostsAny);
        addRow(form, c, row++, "match.pathRegex", pathRegex);
        addRow(form, c, row++, "match.methods", methods);
        addRow(form, c, row++, "match.contentTypesAny", contentTypesAny);
        addRow(form, c, row++, "action.forcePipeline", forcePipeline);
        addRow(form, c, row++, "action.schemaPack", schemaPack);
        addRow(form, c, row++, "action.encodingHeaders", encodingHeaders);
        addRow(form, c, row++, "action.label.from", labelFrom);
        addRow(form, c, row++, "action.label.key", labelKey);

        int res = JOptionPane.showConfirmDialog(
                parent, form, "Edit rule", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return null;

        Rule out = new Rule();
        out.id = trimToNull(id.getText());
        out.name = trimToNull(name.getText());
        out.enabled = enabled.isSelected();
        out.priority = parseInt(priority.getText(), 100);
        out.direction = (Direction) direction.getSelectedItem();

        Match mm = new Match();
        if (m != null) {
            mm.transport = m.transport;
            mm.wsSubprotocol = m.wsSubprotocol;
            mm.headerNamePrefixAny = m.headerNamePrefixAny;
            mm.headers = m.headers;
            mm.anyOf = m.anyOf;
        }
        mm.hostsAny = split(hostsAny.getText());
        mm.pathRegex = trimToNull(pathRegex.getText());
        mm.methods = split(methods.getText());
        mm.contentTypesAny = split(contentTypesAny.getText());
        out.match = mm;

        Action aa = new Action();
        if (a != null) {
            aa.perMessageCodecHeader = a.perMessageCodecHeader;
            aa.schemaSelect = a.schemaSelect;
            aa.rewriteHeader = a.rewriteHeader;
            aa.recomputeSig = a.recomputeSig;
        }
        aa.forcePipeline = split(forcePipeline.getText());
        aa.schemaPack = trimToNull(schemaPack.getText());
        aa.encodingHeaders = split(encodingHeaders.getText());
        String lf = trimToNull(labelFrom.getText());
        String lk = trimToNull(labelKey.getText());
        if (lf != null || lk != null) {
            LabelSpec ls = new LabelSpec();
            if (lin != null) {
                ls.pattern = lin.pattern;
                ls.template = lin.template;
                ls.alsoExtract = lin.alsoExtract;
            }
            ls.from = lf;
            ls.key = lk;
            aa.label = ls;
        }
        out.action = aa;
        return out;
    }

    // ---------- helpers ----------

    private static void addRow(JPanel p, GridBagConstraints c, int row, String label, JComponent field) {
        c.gridx = 0; c.gridy = row; c.weightx = 0;
        c.fill = GridBagConstraints.NONE; c.anchor = GridBagConstraints.LINE_END;
        p.add(new JLabel(label), c);
        c.gridx = 1; c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL; c.anchor = GridBagConstraints.LINE_START;
        p.add(field, c);
    }

    /** Comma-join a list for display; null/empty becomes "". */
    private static String join(List<String> xs) {
        return xs == null ? "" : String.join(", ", xs);
    }

    /** Split a comma list into trimmed non-empty tokens; blank input becomes null (matches nothing set). */
    private static List<String> split(String s) {
        if (s == null) return null;
        List<String> out = new ArrayList<>();
        for (String t : s.split(",")) {
            String v = t.trim();
            if (!v.isEmpty()) out.add(v);
        }
        return out.isEmpty() ? null : out;
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static int parseInt(String s, int def) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return def; }
    }
}
