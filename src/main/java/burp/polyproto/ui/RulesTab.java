package burp.polyproto.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;
import burp.polyproto.burp.RuleStore;
import burp.polyproto.rule.Rule;
import burp.polyproto.rule.RuleCodec;
import burp.polyproto.rule.RuleRegistry;
import burp.polyproto.rule.Ruleset;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumnModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

/**
 * The "Rules" suite tab: a spreadsheet view of the live ruleset plus a raw-JSON editor, both backed
 * by the shared {@link RuleRegistry}. Any table mutation is published straight to the registry and
 * persisted via {@link RuleStore}, so edits take effect on the next decoded message immediately.
 */
public final class RulesTab extends JPanel {

    private final MontoyaApi api;
    private final RuleTableModel model = new RuleTableModel();
    private final JTable table = new JTable(model);
    private final CodeView json;

    public RulesTab(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;
        this.json = new CodeView(api, true);

        model.set(new ArrayList<>(RuleRegistry.get().snapshot()));
        model.onEdit = this::publish;

        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        sizeColumns();
        RuleCellRenderers.install(table, darkTheme());

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Table", buildTablePanel());
        tabs.addTab("JSON", buildJsonPanel());
        add(tabs, BorderLayout.CENTER);

        refreshJson();
    }

    // ---------- table tab ----------

    private JPanel buildTablePanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        bar.add(btn("Add", e -> onAdd()));
        bar.add(btn("Edit", e -> onEdit()));
        bar.add(btn("Duplicate", e -> onDuplicate()));
        bar.add(btn("Delete", e -> onDelete()));
        bar.add(btn("Move Up", e -> onMove(-1)));
        bar.add(btn("Move Down", e -> onMove(1)));
        bar.add(btn("Import", e -> onImport()));
        bar.add(btn("Export", e -> onExport()));
        bar.add(btn("Reset to builtins", e -> onReset()));
        p.add(bar, BorderLayout.SOUTH);
        return p;
    }

    private void onAdd() {
        Rule r = new Rule();
        r.enabled = true;
        r.priority = 100;
        model.add(r);
        int i = model.getRowCount() - 1;
        table.setRowSelectionInterval(i, i);
        publish();
    }

    private void onEdit() {
        int row = table.getSelectedRow();
        if (row < 0) return;
        Rule edited = RuleDialog.edit(this, model.at(row));
        if (edited == null) return;
        model.replace(row, edited);
        table.setRowSelectionInterval(row, row);
        publish();
    }

    private void onDuplicate() {
        int row = table.getSelectedRow();
        if (row < 0) return;
        try {
            Rule copy = deepCopy(model.at(row));
            copy.id = null;
            copy.name = (copy.name == null ? "rule" : copy.name) + " (copy)";
            model.add(copy);
            int i = model.getRowCount() - 1;
            table.setRowSelectionInterval(i, i);
            publish();
        } catch (Exception ex) {
            error("Duplicate failed", ex);
        }
    }

    private void onDelete() {
        int row = table.getSelectedRow();
        if (row < 0) return;
        model.remove(row);
        if (model.getRowCount() > 0) {
            int i = Math.min(row, model.getRowCount() - 1);
            table.setRowSelectionInterval(i, i);
        }
        publish();
    }

    private void onMove(int delta) {
        int row = table.getSelectedRow();
        int target = row + delta;
        if (row < 0 || target < 0 || target >= model.getRowCount()) return;
        model.move(row, target);
        table.setRowSelectionInterval(target, target);
        publish();
    }

    private void onImport() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter("JSON ruleset (*.json)", "json"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            Path path = fc.getSelectedFile().toPath();
            Ruleset rs = RuleCodec.fromJson(Files.readString(path));
            model.set(rs.rules);
            publish();
        } catch (Exception ex) {
            error("Import failed", ex);
        }
    }

    private void onExport() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter("JSON ruleset (*.json)", "json"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            File f = fc.getSelectedFile();
            if (!f.getName().toLowerCase().endsWith(".json")) {
                f = new File(f.getParentFile(), f.getName() + ".json");
            }
            Files.writeString(f.toPath(), RuleCodec.toJson(currentRuleset()));
        } catch (Exception ex) {
            error("Export failed", ex);
        }
    }

    private void onReset() {
        int c = JOptionPane.showConfirmDialog(this,
                "Replace all rules with the bundled builtins?", "Reset to builtins",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (c != JOptionPane.OK_OPTION) return;
        try {
            model.set(RuleStore.builtins(api));
            publish();
        } catch (Exception ex) {
            error("Reset failed", ex);
        }
    }

    // ---------- json tab ----------

    private JPanel buildJsonPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.add(json.getComponent(), BorderLayout.CENTER);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        bar.add(btn("Validate", e -> onValidate()));
        bar.add(btn("Apply from JSON", e -> onApplyJson()));
        p.add(bar, BorderLayout.SOUTH);
        return p;
    }

    private void onValidate() {
        try {
            Ruleset rs = RuleCodec.fromJson(json.getText());
            JOptionPane.showMessageDialog(this,
                    "Valid ruleset (" + rs.rules.size() + " rules).", "Validate",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Invalid JSON: " + ex.getMessage(), "Validate", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onApplyJson() {
        try {
            Ruleset rs = RuleCodec.fromJson(json.getText());
            model.set(rs.rules);
            publish();
            JOptionPane.showMessageDialog(this,
                    "Applied " + rs.rules.size() + " rules.", "Apply from JSON",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Apply failed: " + ex.getMessage(), "Apply from JSON", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ---------- shared ----------

    /** Push the table rows into the live registry, persist, and re-render the JSON view. */
    private void publish() {
        try {
            RuleRegistry.get().set(new ArrayList<>(model.rules()));
            RuleStore.save(api);
            refreshJson();
        } catch (Exception ex) {
            error("Publish failed", ex);
        }
    }

    private void refreshJson() {
        try {
            json.setText(RuleCodec.toJson(currentRuleset()));
        } catch (Exception ex) {
            api.logging().logToError("PolyProto Rules: JSON render failed", ex);
        }
    }

    private Ruleset currentRuleset() {
        Ruleset rs = new Ruleset();
        rs.rules.addAll(model.rules());
        return rs;
    }

    private Rule deepCopy(Rule r) {
        Ruleset one = new Ruleset();
        one.rules.add(r);
        return RuleCodec.fromJson(RuleCodec.toJson(one)).rules.get(0);
    }

    private void sizeColumns() {
        TableColumnModel cm = table.getColumnModel();
        int[] widths = { 36, 48, 170, 66, 240, 150, 96, 120 };
        for (int i = 0; i < widths.length && i < cm.getColumnCount(); i++) {
            cm.getColumn(i).setPreferredWidth(widths[i]);
        }
        cm.getColumn(0).setMaxWidth(44);
    }

    private boolean darkTheme() {
        try {
            return api.userInterface().currentTheme() == Theme.DARK;
        } catch (Exception ex) {
            return false;
        }
    }

    private static JButton btn(String text, ActionListener al) {
        JButton b = new JButton(text);
        b.addActionListener(al);
        return b;
    }

    private void error(String title, Exception ex) {
        api.logging().logToError("PolyProto Rules: " + title, ex);
        JOptionPane.showMessageDialog(this, title + ": " + ex.getMessage(), title, JOptionPane.ERROR_MESSAGE);
    }
}
