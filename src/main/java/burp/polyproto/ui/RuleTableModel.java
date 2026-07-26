package burp.polyproto.ui;

import burp.polyproto.rule.Match;
import burp.polyproto.rule.Rule;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Table view over the editable rule list. Only the "On" toggle is edited in place; every other
 * column is a read-only summary (the full form lives in {@link RuleDialog}). The owning tab wires
 * {@link #onEdit} so a checkbox flip re-publishes the ruleset.
 */
public final class RuleTableModel extends AbstractTableModel {

    private static final String[] COLS =
            { "On", "Prio", "Name", "Dir", "Match", "Pipeline", "Pack", "Label" };

    private final List<Rule> rules = new ArrayList<>();

    /** Invoked when a user edits a cell in place (the "On" toggle); lets the tab re-publish. */
    Runnable onEdit;

    /** Live backing list (table order). Mutations should go through the methods below. */
    public List<Rule> rules() { return rules; }

    public Rule at(int row) { return rules.get(row); }

    public void set(List<Rule> rs) {
        rules.clear();
        if (rs != null) rules.addAll(rs);
        fireTableDataChanged();
    }

    public void add(Rule r) {
        rules.add(r);
        int i = rules.size() - 1;
        fireTableRowsInserted(i, i);
    }

    public void replace(int row, Rule r) {
        if (row < 0 || row >= rules.size()) return;
        rules.set(row, r);
        fireTableRowsUpdated(row, row);
    }

    public void remove(int row) {
        if (row < 0 || row >= rules.size()) return;
        rules.remove(row);
        fireTableRowsDeleted(row, row);
    }

    /** Swap two rows and swap their priorities so each position keeps its priority (sort-stable). */
    public void move(int from, int to) {
        if (from < 0 || to < 0 || from >= rules.size() || to >= rules.size() || from == to) return;
        int p = rules.get(from).priority;
        rules.get(from).priority = rules.get(to).priority;
        rules.get(to).priority = p;
        Collections.swap(rules, from, to);
        fireTableRowsUpdated(Math.min(from, to), Math.max(from, to));
    }

    // ---------- AbstractTableModel ----------

    @Override public int getRowCount() { return rules.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int c) { return COLS[c]; }

    @Override
    public Class<?> getColumnClass(int c) {
        if (c == 0) return Boolean.class;
        if (c == 1) return Integer.class;
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int col) { return col == 0; }

    @Override
    public Object getValueAt(int row, int col) {
        Rule r = rules.get(row);
        switch (col) {
            case 0:  return r.enabled;
            case 1:  return r.priority;
            case 2:  return r.name == null ? "" : r.name;
            case 3:  return r.direction == null ? "BOTH" : r.direction.name();
            case 4:  return matchSummary(r.match);
            case 5:  return pipeline(r);
            case 6:  return r.action == null || r.action.schemaPack == null ? "" : r.action.schemaPack;
            case 7:  return r.action == null || r.action.label == null || r.action.label.from == null
                            ? "" : r.action.label.from;
            default: return "";
        }
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if (col != 0 || row < 0 || row >= rules.size()) return;
        rules.get(row).enabled = Boolean.TRUE.equals(value);
        fireTableCellUpdated(row, col);
        if (onEdit != null) onEdit.run();
    }

    // ---------- summaries ----------

    private static String matchSummary(Match m) {
        if (m == null) return "";
        List<String> parts = new ArrayList<>();
        if (m.hostsAny != null) parts.addAll(m.hostsAny);
        if (m.pathRegex != null && !m.pathRegex.isEmpty()) parts.add(m.pathRegex);
        if (m.contentTypesAny != null) parts.addAll(m.contentTypesAny);
        return String.join("  ", parts);
    }

    private static String pipeline(Rule r) {
        if (r.action == null || r.action.forcePipeline == null || r.action.forcePipeline.isEmpty()) return "auto";
        return String.join(" ", r.action.forcePipeline);
    }
}
