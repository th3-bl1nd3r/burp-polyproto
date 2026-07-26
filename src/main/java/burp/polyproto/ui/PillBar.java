package burp.polyproto.ui;

import burp.polyproto.core.DecodeResult;

import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * The decoded-tab breadcrumb: the detected layers as rounded pills (chunked › gzip › protobuf,
 * the terminal format emphasized in the accent color) plus state chips — matched rule, faithful /
 * identity-fallback, and the extracted label. Scans at a glance instead of one grey line of text.
 */
public final class PillBar extends JPanel {
    private final boolean dark;
    private final Color pillBg, pillFg, border, accent, accentBg, good, warn, dim;
    private final Font mono;

    public PillBar(boolean dark) {
        this.dark = dark;
        setLayout(new FlowLayout(FlowLayout.LEFT, 5, 4));
        setOpaque(false);
        mono = new Font(Font.MONOSPACED, Font.PLAIN, 11);
        if (dark) {
            pillBg = new Color(0x1B2438); pillFg = new Color(0xC7D0E4); border = new Color(0x2A3450);
            accent = new Color(0xE89658); accentBg = new Color(0x2A1D12);   // copper on ink
            good = new Color(0x66D69A); warn = new Color(0xE3C36A); dim = new Color(0x6B7796);
        } else {
            pillBg = new Color(0xEEF1F7); pillFg = new Color(0x25303B); border = new Color(0xDCE1EC);
            accent = new Color(0xB4632A); accentBg = new Color(0xF6E7DA);
            good = new Color(0x12783F); warn = new Color(0x8A6D1F); dim = new Color(0x6A7590);
        }
    }

    /** Populate from a decode result. Safe to call repeatedly. */
    public void show(DecodeResult r) {
        removeAll();
        String bc = r.breadcrumb == null || r.breadcrumb.isEmpty()
                ? String.valueOf(r.terminalFormat) : r.breadcrumb;
        String[] layers = bc.split(" › ");
        for (int i = 0; i < layers.length; i++) {
            boolean terminal = i == layers.length - 1;
            add(new Pill(layers[i].trim(),
                    terminal ? accentBg : pillBg,
                    terminal ? accent : pillFg,
                    terminal ? accent : border, true));
            if (i < layers.length - 1) add(sep());
        }
        if (r.matchedRuleName != null) add(chip("via " + shorten(r.matchedRuleName, 26), dim));
        if (r.label != null && !r.label.isEmpty()) add(chip("● " + shorten(r.label, 30), accent));
        if (!r.faithful) add(chip("⚠ identity-fallback", warn));
        else add(chip("faithful ✓", good));
        revalidate();
        repaint();
    }

    private JLabel sep() {
        JLabel s = new JLabel("›");
        s.setForeground(dim);
        return s;
    }

    private Pill chip(String text, Color fg) {
        return new Pill(text, pillBg, fg, border, false);
    }

    private static String shorten(String s, int n) {
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    /** A rounded, self-painting label. */
    private final class Pill extends JLabel {
        private final Color bg, brd;
        Pill(String text, Color bg, Color fg, Color brd, boolean strong) {
            super(text);
            this.bg = bg; this.brd = brd;
            setOpaque(false);
            setForeground(fg);
            setFont(strong ? mono.deriveFont(Font.BOLD) : mono);
            setBorder(javax.swing.BorderFactory.createEmptyBorder(2, 9, 2, 9));
        }

        @Override public Dimension getPreferredSize() {
            Dimension d = super.getPreferredSize();
            d.height += 2;
            return d;
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int arc = getHeight();
            g2.setColor(bg);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            g2.setColor(brd);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            g2.dispose();
            super.paintComponent(g);
        }
    }
}
