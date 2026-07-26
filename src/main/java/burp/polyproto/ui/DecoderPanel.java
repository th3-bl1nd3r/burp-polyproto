package burp.polyproto.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;
import burp.polyproto.core.DecodeResult;
import burp.polyproto.protobuf.ProtoNodes;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/**
 * The per-message decoded tab: a pill breadcrumb + state chips, a toolbar (Tree⇄Text, Copy), a dim
 * note line, and the body — a foldable {@link ProtoTreeView} for protobuf (read), or the editable
 * {@link CodeView} (which carries its own find bar). Non-protobuf bodies show the text view only.
 */
public final class DecoderPanel {
    private final JPanel root;
    private final PillBar pills;
    private final JLabel note;
    private final CodeView view;
    private final ProtoTreeView treeView;
    private final JPanel center;
    private final CardLayout cards;
    private final JButton toggle;

    private boolean hasTree;
    private boolean treeShown;

    public DecoderPanel(MontoyaApi api, boolean editable) {
        boolean dark;
        try { dark = api.userInterface().currentTheme() == Theme.DARK; } catch (Exception e) { dark = false; }

        view = new CodeView(api, editable);
        treeView = new ProtoTreeView(dark);
        pills = new PillBar(dark);

        note = new JLabel(" ");
        note.putClientProperty("html.disable", Boolean.TRUE);
        note.setForeground(dark ? new Color(0x6B7796) : new Color(0x6A7590));
        note.setFont(note.getFont().deriveFont(Font.ITALIC, note.getFont().getSize2D() - 1f));

        toggle = mini("≡ Text", "Switch between the folding tree and the editable text", e -> toggle());
        toggle.setVisible(false);
        JButton copy = mini("⧉ Copy", "Copy the decoded text", e ->
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(view.getText()), null));

        JPanel toolbar = new JPanel();
        toolbar.setOpaque(false);
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.X_AXIS));
        toolbar.add(toggle);
        toolbar.add(copy);

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.setOpaque(false);
        topRow.add(pills, BorderLayout.CENTER);
        topRow.add(toolbar, BorderLayout.EAST);
        topRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        note.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel header = new JPanel();
        header.setOpaque(false);
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 8));
        header.add(topRow);
        header.add(note);

        cards = new CardLayout();
        center = new JPanel(cards);
        center.add(view.getComponent(), "text");
        center.add(treeView, "tree");

        root = new JPanel(new BorderLayout());
        root.add(header, BorderLayout.NORTH);
        root.add(center, BorderLayout.CENTER);
    }

    public void show(DecodeResult r) {
        pills.show(r);
        note.setText(r.note == null || r.note.isEmpty() ? " " : r.note);
        view.setText(r.text == null ? "" : r.text);

        hasTree = r.terminalBytes != null && r.terminalBytes.length > 0;
        if (hasTree) {
            try {
                treeView.setRoot(ProtoNodes.parse(r.terminalBytes, r.schema));
                toggle.setVisible(true);
                showTree(true); // tree-first for protobuf; one click to edit
            } catch (Exception e) {
                toggle.setVisible(false);
                showTree(false);
            }
        } else {
            toggle.setVisible(false);
            showTree(false);
        }
    }

    private void toggle() { showTree(!treeShown); }

    private void showTree(boolean t) {
        treeShown = t && hasTree;
        cards.show(center, treeShown ? "tree" : "text");
        toggle.setText(treeShown ? "≡ Text" : "⌗ Tree");
    }

    public String getText() { return view.getText(); }
    public boolean isModified() { return view.isModified(); }
    public Component getComponent() { return root; }

    private static JButton mini(String text, String tip, java.awt.event.ActionListener onClick) {
        JButton b = new JButton(text);
        b.setToolTipText(tip);
        b.setFocusable(false);
        b.setMargin(new Insets(2, 8, 2, 8));
        b.putClientProperty("JButton.buttonType", "toolBarButton");
        b.addActionListener(onClick);
        return b;
    }
}
