package burp.polyproto.ui;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * Swing cell renderers that dress up the {@link RuleTableModel} table: a pill-shaped toggle for the
 * "On" boolean, a band-colored monospaced "Prio", "Pipeline" tokens drawn as rounded chips, and an
 * ellipsized "Match" that keeps its full text in the tooltip. Renderers are matched by column header
 * name (case-insensitively) rather than by index, so they survive column reordering/renumbering.
 */
public final class RuleCellRenderers {

    private RuleCellRenderers() { }

    /** Install the polished renderers on the "On"/"Prio"/"Pipeline"/"Match" columns of {@code table}. */
    public static void install(JTable table, boolean dark) {
        TableColumnModel cm = table.getColumnModel();
        for (int i = 0; i < table.getColumnCount(); i++) {
            String name = table.getColumnName(i);
            if (name == null) continue;
            TableColumn col = cm.getColumn(i);
            if (name.equalsIgnoreCase("On")) {
                col.setCellRenderer(new TogglePillRenderer(dark));
            } else if (name.equalsIgnoreCase("Prio")) {
                col.setCellRenderer(new PriorityRenderer(dark));
            } else if (name.equalsIgnoreCase("Pipeline")) {
                col.setCellRenderer(new PipelineRenderer(dark));
            } else if (name.equalsIgnoreCase("Match")) {
                col.setCellRenderer(new MatchRenderer());
            }
        }
        // Give the pills a little vertical breathing room.
        if (table.getRowHeight() < 24) table.setRowHeight(24);
    }

    // ---------- "On": a small rounded toggle-switch ----------

    private static final class TogglePillRenderer extends JComponent implements TableCellRenderer {
        private final Color trackOn, trackOff, knob;
        private boolean on;
        private Color cellBg;

        TogglePillRenderer(boolean dark) {
            trackOn  = new Color(dark ? 0xE89658 : 0xB4632A);   // copper = enabled/active
            trackOff = new Color(dark ? 0x2A3450 : 0xC7CDD4);
            knob     = new Color(dark ? 0xF0F6FC : 0xFFFFFF);
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            on = Boolean.TRUE.equals(value);
            cellBg = isSelected ? table.getSelectionBackground() : table.getBackground();
            return this;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(cellBg);
            g2.fillRect(0, 0, getWidth(), getHeight());

            int trackW = 26, trackH = 14;
            int x = (getWidth() - trackW) / 2;
            int y = (getHeight() - trackH) / 2;
            g2.setColor(on ? trackOn : trackOff);
            g2.fillRoundRect(x, y, trackW, trackH, trackH, trackH);

            int knobD = trackH - 4;
            int knobX = on ? x + trackW - knobD - 2 : x + 2;
            int knobY = y + 2;
            g2.setColor(knob);
            g2.fillOval(knobX, knobY, knobD, knobD);
            g2.dispose();
        }
    }

    // ---------- "Prio": right-aligned monospaced, colored by band ----------

    private static final class PriorityRenderer extends DefaultTableCellRenderer {
        private final Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        private final Color hi, mid, dim;

        PriorityRenderer(boolean dark) {
            hi  = new Color(dark ? 0xFF6B6B : 0xCF3B3B);
            mid = new Color(dark ? 0xE3C36A : 0x8A6D1F);
            dim = new Color(dark ? 0x6B7796 : 0x8592A6);
            setHorizontalAlignment(SwingConstants.RIGHT);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setFont(mono);
            setHorizontalAlignment(SwingConstants.RIGHT);
            if (!isSelected) {
                int p = toInt(value);
                Color c;
                if (p >= 800)      c = hi;
                else if (p >= 500) c = mid;
                else if (p >= 100) c = table.getForeground();
                else               c = dim;
                setForeground(c);
            }
            return this;
        }

        private static int toInt(Object value) {
            if (value instanceof Integer) return (Integer) value;
            if (value == null) return 0;
            try {
                return Integer.parseInt(value.toString().trim());
            } catch (NumberFormatException e) {
                return 0;
            }
        }
    }

    // ---------- "Pipeline": tokens drawn as rounded chips ----------

    private static final class PipelineRenderer extends JComponent implements TableCellRenderer {
        private final Font font = new Font(Font.MONOSPACED, Font.PLAIN, 11);
        private final Color chipBg, chipBorder, chipFg;
        private String[] tokens = new String[0];
        private Color cellBg;

        PipelineRenderer(boolean dark) {
            chipBg     = new Color(dark ? 0x1B2438 : 0xEEF1F7);
            chipBorder = new Color(dark ? 0x2A3450 : 0xDCE1EC);
            chipFg     = new Color(dark ? 0xC7D0E4 : 0x1B2233);
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            String s = value == null ? "" : value.toString().trim();
            tokens = s.isEmpty() ? new String[0] : s.split("[\\s,]+");
            cellBg = isSelected ? table.getSelectionBackground() : table.getBackground();
            setToolTipText(s.isEmpty() ? null : s);
            return this;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(cellBg);
            g2.fillRect(0, 0, getWidth(), getHeight());

            g2.setFont(font);
            FontMetrics fm = g2.getFontMetrics();
            int padX = 6, gap = 4;
            int h = fm.getHeight() - 2;
            int y = (getHeight() - h) / 2;
            int x = 4;
            int limit = getWidth() - 4;

            for (String tok : tokens) {
                if (tok.isEmpty()) continue;
                int tw = fm.stringWidth(tok);
                int chipW = tw + padX * 2;
                if (x + chipW > limit) {
                    g2.setColor(chipFg);
                    g2.drawString("…", x, y + fm.getAscent() - 1);
                    break;
                }
                g2.setColor(chipBg);
                g2.fillRoundRect(x, y, chipW, h, h, h);
                g2.setColor(chipBorder);
                g2.drawRoundRect(x, y, chipW, h, h, h);
                g2.setColor(chipFg);
                g2.drawString(tok, x + padX, y + fm.getAscent() - 1);
                x += chipW + gap;
            }
            g2.dispose();
        }
    }

    // ---------- "Match": ellipsized, full text in the tooltip ----------

    private static final class MatchRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String s = value == null ? "" : value.toString();
            setToolTipText(s.isEmpty() ? null : s);
            return this;
        }
    }
}
