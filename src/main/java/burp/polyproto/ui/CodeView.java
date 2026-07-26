package burp.polyproto.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.KeyStroke;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * A colored, line-numbered, non-wrapping text view/editor for the decoded formats
 * (Frontier frame text, protobuf field tree, JSON). Theme-aware (Burp light/dark).
 * Replaces Burp's monochrome RawEditor so the output is readable.
 */
public class CodeView {

    // token patterns (applied in order; later overrides earlier via replace=true)
    private static final Pattern RE_NUMBER  = Pattern.compile("\\b\\d+\\b");
    private static final Pattern RE_KEYWORD = Pattern.compile(
            "(?m)^(seqid|logid|service|method|payload_encoding|payload_type|logidnew|server_timing|msg_id|header)\\b");
    private static final Pattern RE_TREEKEY = Pattern.compile("(?m)^\\s*\\d+\\s+([A-Za-z_][\\w]*)");
    private static final Pattern RE_HEADERK = Pattern.compile("(?m)^header\\s+([^:\\n]+):");
    private static final Pattern RE_BRACE   = Pattern.compile("[\\{\\}\\[\\]]");
    private static final Pattern RE_COMMENT = Pattern.compile("//[^\\n]*");
    private static final Pattern RE_MARKER  = Pattern.compile("(?m)^---.*---\\s*$");
    private static final Pattern RE_STRING  = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"");
    private static final Pattern RE_JSONKEY = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"(?=\\s*:)");

    private final JTextPane pane;
    private final JScrollPane scroll;
    private final Gutter gutter;
    private final Timer highlightTimer;

    private final SimpleAttributeSet sDefault = new SimpleAttributeSet();
    private final SimpleAttributeSet sKeyword = new SimpleAttributeSet();
    private final SimpleAttributeSet sString = new SimpleAttributeSet();
    private final SimpleAttributeSet sNumber = new SimpleAttributeSet();
    private final SimpleAttributeSet sComment = new SimpleAttributeSet();
    private final SimpleAttributeSet sMarker = new SimpleAttributeSet();
    private final SimpleAttributeSet sHeaderKey = new SimpleAttributeSet();
    private final SimpleAttributeSet sBrace = new SimpleAttributeSet();

    private Color gutterFg;
    private boolean settingText = false;
    private boolean modified = false;

    // find bar
    private final JPanel root;
    private JPanel findBar;
    private JTextField findQuery;
    private JLabel findCount;
    private JToggleButton findCase, findRegex;
    private Highlighter.HighlightPainter matchPainter, currentPainter;
    private Color countFg, errColor;
    private final List<int[]> matches = new ArrayList<>();
    private int currentMatch = -1;
    private Timer findTimer;

    // undo/redo (like Burp's editor); syntax-highlight attribute edits are filtered out
    private final javax.swing.undo.UndoManager undo = new javax.swing.undo.UndoManager();

    public CodeView(MontoyaApi api, boolean editable) {
        boolean dark = safeDark(api);
        Color bg, fg, gutterBg;
        if (dark) {
            bg = new Color(0x141B2D); fg = new Color(0xC7D0E4);   // indigo-ink panel, cool text
            gutterBg = new Color(0x0C1120); gutterFg = new Color(0x4A5573);
            style(sKeyword, 0x77B0FF, true);   // field names / keys: periwinkle-blue
            style(sString, 0x66D69A, false);   // strings: green
            style(sNumber, 0xE3C36A, false);   // numbers: warm yellow
            style(sComment, 0x5A6480, false);  // comments: dim
            style(sMarker, 0xE89658, true);    // section markers: copper (the signal accent)
            style(sHeaderKey, 0xB79BFF, false);// header keys / enums: iris
            style(sBrace, 0x4A5573, true);     // braces: wire-dim
        } else {
            bg = Color.WHITE; fg = new Color(0x1B2233);
            gutterBg = new Color(0xF1F3F8); gutterFg = new Color(0x9AA3B5);
            style(sKeyword, 0x1D5FD6, true);
            style(sString, 0x12783F, false);
            style(sNumber, 0x8A6D1F, false);
            style(sComment, 0x8B93A5, false);
            style(sMarker, 0xB4632A, true);    // copper (dark variant)
            style(sHeaderKey, 0x6B44C9, false);
            style(sBrace, 0xAEB6C6, true);
        }
        StyleConstants.setForeground(sDefault, fg);

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 13);
        pane = new JTextPane() {
            @Override
            public boolean getScrollableTracksViewportWidth() {
                Component parent = getParent();
                if (parent == null) return true;
                return getUI().getPreferredSize(this).width <= parent.getWidth();
            }
        };
        pane.setFont(mono);
        pane.setEditable(editable);
        pane.setBackground(bg);
        pane.setForeground(fg);
        pane.setCaretColor(fg);
        pane.setBorder(javax.swing.BorderFactory.createEmptyBorder(2, 6, 2, 6));

        gutter = new Gutter(gutterBg);
        scroll = new JScrollPane(pane);
        scroll.setRowHeaderView(gutter);
        scroll.getViewport().setBackground(bg);
        scroll.setBorder(javax.swing.BorderFactory.createEmptyBorder());

        highlightTimer = new Timer(120, e -> highlight());
        highlightTimer.setRepeats(false);

        // find bar: painters + bar + keybindings, wrapped with the scroll pane in `root`
        Color matchBg = dark ? new Color(0x585230) : new Color(0xFBEEA6);
        Color curBg   = dark ? new Color(0x7C4E28) : new Color(0xF3C79A); // current match: copper
        matchPainter   = new DefaultHighlighter.DefaultHighlightPainter(matchBg);
        currentPainter = new DefaultHighlighter.DefaultHighlightPainter(curBg);
        countFg = fg;
        errColor = dark ? new Color(0xE06C75) : new Color(0xC0392B);
        buildFindBar(dark, gutterBg, fg);
        root = new JPanel(new BorderLayout());
        root.add(scroll, BorderLayout.CENTER);
        root.add(findBar, BorderLayout.SOUTH);
        installFindKeys();
        findTimer = new Timer(150, e -> { if (findBar.isVisible()) runFind(); });
        findTimer.setRepeats(false);

        pane.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { onEdit(); }
            @Override public void removeUpdate(DocumentEvent e) { onEdit(); }
            @Override public void changedUpdate(DocumentEvent e) { /* attribute-only change */ }
        });

        installUndo();
    }

    /** Wire an UndoManager with Ctrl/Cmd+Z (undo) and Ctrl/Cmd+Shift+Z / Ctrl/Cmd+Y (redo). */
    private void installUndo() {
        undo.setLimit(500);
        pane.getDocument().addUndoableEditListener(e -> {
            javax.swing.undo.UndoableEdit ed = e.getEdit();
            // ignore the syntax highlighter's attribute-only edits — only real text edits are undoable
            if (ed instanceof javax.swing.text.AbstractDocument.DefaultDocumentEvent
                    && ((javax.swing.text.AbstractDocument.DefaultDocumentEvent) ed).getType()
                        == DocumentEvent.EventType.CHANGE) {
                return;
            }
            undo.addEdit(ed);
        });
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        InputMap im = pane.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = pane.getActionMap();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask), "codec.undo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask | KeyEvent.SHIFT_DOWN_MASK), "codec.redo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, mask), "codec.redo");
        am.put("codec.undo", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                try { if (undo.canUndo()) undo.undo(); } catch (Exception ex) { /* nothing to undo */ }
            }
        });
        am.put("codec.redo", new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) {
                try { if (undo.canRedo()) undo.redo(); } catch (Exception ex) { /* nothing to redo */ }
            }
        });
    }

    public Component getComponent() { return root; }

    public boolean isModified() { return modified; }

    public String getText() {
        try {
            return pane.getDocument().getText(0, pane.getDocument().getLength());
        } catch (BadLocationException e) {
            return pane.getText();
        }
    }

    public void setText(String s) {
        settingText = true;
        pane.setText(s == null ? "" : s);
        pane.setCaretPosition(0);
        highlight();
        modified = false;
        settingText = false;
        refreshGutter();
        undo.discardAllEdits(); // fresh message → no undo back into the previous one
        if (findBar != null && findBar.isVisible()) runFind();
    }

    private void onEdit() {
        if (settingText) return;
        modified = true;
        highlightTimer.restart();
        refreshGutter();
        if (findBar != null && findBar.isVisible() && findTimer != null) findTimer.restart();
    }

    private void refreshGutter() {
        SwingUtilities.invokeLater(() -> { gutter.revalidate(); gutter.repaint(); });
    }

    private void highlight() {
        StyledDocument doc = pane.getStyledDocument();
        String text;
        try {
            text = doc.getText(0, doc.getLength());
        } catch (BadLocationException e) {
            return;
        }
        doc.setCharacterAttributes(0, doc.getLength(), sDefault, true);
        apply(doc, text, RE_NUMBER, sNumber, 0);
        apply(doc, text, RE_KEYWORD, sKeyword, 1);
        apply(doc, text, RE_TREEKEY, sKeyword, 1);
        apply(doc, text, RE_HEADERK, sHeaderKey, 1);
        apply(doc, text, RE_BRACE, sBrace, 0);
        apply(doc, text, RE_COMMENT, sComment, 0);
        apply(doc, text, RE_MARKER, sMarker, 0);
        apply(doc, text, RE_STRING, sString, 0);
        apply(doc, text, RE_JSONKEY, sKeyword, 0);
    }

    private void apply(StyledDocument doc, String text, Pattern p, SimpleAttributeSet attr, int group) {
        Matcher m = p.matcher(text);
        while (m.find()) {
            int start = group == 0 ? m.start() : m.start(group);
            int end = group == 0 ? m.end() : m.end(group);
            if (start >= 0 && end > start) {
                doc.setCharacterAttributes(start, end - start, attr, true);
            }
        }
    }

    private static void style(SimpleAttributeSet s, int rgb, boolean bold) {
        StyleConstants.setForeground(s, new Color(rgb));
        if (bold) StyleConstants.setBold(s, true);
    }

    private static boolean safeDark(MontoyaApi api) {
        try {
            return api.userInterface().currentTheme() == Theme.DARK;
        } catch (Exception e) {
            return false;
        }
    }

    // ===================== find bar (Ctrl/Cmd+F) =====================

    /** Focus the (always-visible) find field; seeds the query from a single-line selection. */
    public void showFind() {
        String sel = pane.getSelectedText();
        if (sel != null && !sel.isEmpty() && sel.indexOf('\n') < 0) findQuery.setText(sel);
        runFind();
        findQuery.requestFocusInWindow();
        findQuery.selectAll();
    }

    private void buildFindBar(boolean dark, Color barBg, Color fg) {
        findBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
        findBar.setBackground(barBg);
        findBar.setBorder(javax.swing.BorderFactory.createMatteBorder(
                1, 0, 0, 0, dark ? new Color(0x214283) : new Color(0xBBBBBB)));
        // Always shown at the bottom of the decoded view, like Burp's native editor find bar.

        JLabel lbl = new JLabel("Find:");
        lbl.setForeground(fg);
        findQuery = new JTextField(24);
        findQuery.setToolTipText("Find in decoded view (Enter = next, Shift+Enter = previous, Esc = clear)");
        findCount = new JLabel("");
        findCount.setForeground(countFg);

        JButton prev = mini("▲", "Previous match (Shift+Enter / Shift+F3)");
        JButton next = mini("▼", "Next match (Enter / F3)");
        findCase = miniToggle("Aa", "Case sensitive");
        findRegex = miniToggle(".*", "Regular expression");

        prev.addActionListener(e -> navigate(-1));
        next.addActionListener(e -> navigate(1));
        findCase.addActionListener(e -> runFind());
        findRegex.addActionListener(e -> runFind());
        findQuery.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { runFind(); }
            @Override public void removeUpdate(DocumentEvent e) { runFind(); }
            @Override public void changedUpdate(DocumentEvent e) { }
        });

        findBar.add(lbl); findBar.add(findQuery); findBar.add(findCount);
        findBar.add(prev); findBar.add(next);
        findBar.add(findCase); findBar.add(findRegex);

        InputMap im = findQuery.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = findQuery.getActionMap();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "next");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.SHIFT_DOWN_MASK), "prev");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "clear");
        am.put("next", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { navigate(1); } });
        am.put("prev", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { navigate(-1); } });
        am.put("clear", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { findQuery.setText(""); } });
    }

    private void installFindKeys() {
        bindFindKeys(pane.getInputMap(JComponent.WHEN_FOCUSED), pane.getActionMap());
        bindFindKeys(root.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT), root.getActionMap());
    }

    private void bindFindKeys(InputMap im, ActionMap am) {
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_F, menuMask), "codec.find");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), "codec.findNext");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_F3, KeyEvent.SHIFT_DOWN_MASK), "codec.findPrev");
        am.put("codec.find", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { showFind(); } });
        am.put("codec.findNext", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { if (findBar.isVisible()) navigate(1); else showFind(); } });
        am.put("codec.findPrev", new AbstractAction() { @Override public void actionPerformed(ActionEvent e) { if (findBar.isVisible()) navigate(-1); else showFind(); } });
    }

    private JButton mini(String text, String tip) {
        JButton b = new JButton(text);
        b.setToolTipText(tip);
        b.setMargin(new Insets(1, 6, 1, 6));
        b.setFocusable(false);
        return b;
    }

    private JToggleButton miniToggle(String text, String tip) {
        JToggleButton b = new JToggleButton(text);
        b.setToolTipText(tip);
        b.setMargin(new Insets(1, 6, 1, 6));
        b.setFocusable(false);
        return b;
    }

    /** Recompute all matches for the current query and repaint the highlight layer. */
    private void runFind() {
        Highlighter hl = pane.getHighlighter();
        hl.removeAllHighlights();
        matches.clear();
        currentMatch = -1;
        String q = findQuery.getText();
        if (q == null || q.isEmpty()) { findCount.setText(""); findCount.setForeground(countFg); return; }
        String text = getText();
        try {
            if (findRegex.isSelected()) {
                int flags = findCase.isSelected() ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
                Matcher m = Pattern.compile(q, flags).matcher(text);
                while (m.find()) {
                    if (m.end() > m.start()) matches.add(new int[]{ m.start(), m.end() });
                    else break; // zero-width match guard
                }
            } else {
                String hay = findCase.isSelected() ? text : text.toLowerCase();
                String needle = findCase.isSelected() ? q : q.toLowerCase();
                int idx = 0;
                while ((idx = hay.indexOf(needle, idx)) >= 0) {
                    matches.add(new int[]{ idx, idx + needle.length() });
                    idx += needle.length();
                }
            }
        } catch (Exception ex) {
            findCount.setText("bad regex");
            findCount.setForeground(errColor);
            return;
        }
        if (matches.isEmpty()) {
            findCount.setText("No matches");
            findCount.setForeground(errColor);
            return;
        }
        int caret = pane.getCaretPosition();
        currentMatch = 0;
        for (int i = 0; i < matches.size(); i++) {
            if (matches.get(i)[0] >= caret) { currentMatch = i; break; }
        }
        renderHighlights();
        scrollToCurrent();
        updateCount();
    }

    private void navigate(int dir) {
        if (matches.isEmpty()) { runFind(); return; }
        currentMatch = (currentMatch + dir + matches.size()) % matches.size();
        renderHighlights();
        scrollToCurrent();
        updateCount();
    }

    private void renderHighlights() {
        Highlighter hl = pane.getHighlighter();
        hl.removeAllHighlights();
        try {
            for (int i = 0; i < matches.size(); i++) {
                int[] mth = matches.get(i);
                hl.addHighlight(mth[0], mth[1], i == currentMatch ? currentPainter : matchPainter);
            }
        } catch (BadLocationException ignore) {
            // offsets shifted mid-edit; the next runFind() fixes it
        }
    }

    private void scrollToCurrent() {
        if (currentMatch < 0 || currentMatch >= matches.size()) return;
        try {
            Rectangle r = pane.modelToView(matches.get(currentMatch)[0]);
            Rectangle r2 = pane.modelToView(matches.get(currentMatch)[1]);
            if (r != null) {
                if (r2 != null) r = r.union(r2);
                pane.scrollRectToVisible(r);
            }
        } catch (BadLocationException ignore) { }
    }

    private void updateCount() {
        findCount.setForeground(countFg);
        findCount.setText((currentMatch + 1) + " of " + matches.size());
    }

    /** Line-number gutter painted from the text pane's own layout (wrap-free, so 1 row per line). */
    private final class Gutter extends JPanel {
        Gutter(Color bg) {
            setBackground(bg);
            setBorder(javax.swing.BorderFactory.createEmptyBorder(2, 6, 2, 8));
        }

        @Override
        public Dimension getPreferredSize() {
            int lines = pane.getDocument().getDefaultRootElement().getElementCount();
            FontMetrics fm = pane.getFontMetrics(pane.getFont());
            int digits = Math.max(2, String.valueOf(Math.max(1, lines)).length());
            int w = fm.charWidth('0') * digits + 16;
            int h = Math.max(pane.getPreferredSize().height, pane.getHeight());
            return new Dimension(w, h);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            g.setFont(pane.getFont());
            g.setColor(gutterFg);
            FontMetrics fm = g.getFontMetrics();
            Element root = pane.getDocument().getDefaultRootElement();
            int n = root.getElementCount();
            for (int i = 0; i < n; i++) {
                try {
                    int off = root.getElement(i).getStartOffset();
                    Rectangle r = pane.modelToView(off);
                    if (r == null) continue;
                    String num = String.valueOf(i + 1);
                    int y = r.y + fm.getAscent();
                    int x = getWidth() - fm.stringWidth(num) - 8;
                    g.drawString(num, x, y);
                } catch (BadLocationException ignore) {
                    // line not laid out yet
                }
            }
        }
    }
}
