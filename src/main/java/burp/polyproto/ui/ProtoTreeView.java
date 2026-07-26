package burp.polyproto.ui;

import burp.polyproto.protobuf.ProtoNode;
import burp.polyproto.protobuf.ProtoNodes;
import burp.polyproto.protobuf.Protobuf;
import burp.polyproto.stage.format.ProtobufStage;
import burp.polyproto.util.Compression;

import javax.swing.BorderFactory;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Foldable, syntax-colored view of a decoded protobuf message. Nested messages fold; bytes fields
 * show a {@code ‹bytes› N B} chip; right-click copies value / hex / field-path and re-decodes a
 * bytes field in place as protobuf / gzip / base64 / utf-8 (turning an opaque blob into a subtree).
 */
public final class ProtoTreeView extends JPanel {
    private final JTree tree;
    private final DefaultTreeModel model;
    private final Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 13);

    private final Color bg, fg, fnum, fname, type, str, num, bytes, brace, chipBg, chipBd, sel, dim;

    public ProtoTreeView(boolean dark) {
        super(new BorderLayout());
        if (dark) {
            bg = new Color(0x141B2D); fg = new Color(0xC7D0E4); fnum = new Color(0x5C6785);
            fname = new Color(0x77B0FF); type = new Color(0xE89658); str = new Color(0x66D69A);
            num = new Color(0xE3C36A); bytes = new Color(0x8A94AC); brace = new Color(0x4A5573);
            chipBg = new Color(0x1B2438); chipBd = new Color(0x2A3450); sel = new Color(0x1E2A44);
            dim = new Color(0x6B7796);
        } else {
            bg = Color.WHITE; fg = new Color(0x1B2233); fnum = new Color(0x8592A6);
            fname = new Color(0x1D5FD6); type = new Color(0xB4632A); str = new Color(0x12783F);
            num = new Color(0x8A6D1F); bytes = new Color(0x58627A); brace = new Color(0xAEB6C6);
            chipBg = new Color(0xEEF1F7); chipBd = new Color(0xDCE1EC); sel = new Color(0xE6ECF9);
            dim = new Color(0x8592A6);
        }

        model = new DefaultTreeModel(new DefaultMutableTreeNode(ProtoNode.root()));
        tree = new JTree(model);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setRowHeight(21);
        tree.setBackground(bg);
        tree.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setCellRenderer(new Cell());
        tree.putClientProperty("JTree.lineStyle", "Angled");
        tree.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybePopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybePopup(e); }
        });

        JScrollPane sp = new JScrollPane(tree);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getViewport().setBackground(bg);
        add(sp, BorderLayout.CENTER);
    }

    /** Load a decoded message. Expands the first two levels. */
    public void setRoot(ProtoNode root) {
        DefaultMutableTreeNode r = new DefaultMutableTreeNode(root);
        build(r, root);
        model.setRoot(r);
        // expand top two levels
        for (int i = 0; i < tree.getRowCount(); i++) {
            TreePath p = tree.getPathForRow(i);
            if (p != null && p.getPathCount() <= 3) tree.expandRow(i);
        }
    }

    private void build(DefaultMutableTreeNode dmt, ProtoNode pn) {
        dmt.removeAllChildren();
        for (ProtoNode c : pn.children) {
            DefaultMutableTreeNode cn = new DefaultMutableTreeNode(c);
            if (c.hasChildren()) build(cn, c);
            dmt.add(cn);
        }
    }

    // ---- context menu / decode-in-place ----

    private void maybePopup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int row = tree.getClosestRowForLocation(e.getX(), e.getY());
        if (row < 0) return;
        tree.setSelectionRow(row);
        TreePath path = tree.getPathForRow(row);
        DefaultMutableTreeNode dmt = (DefaultMutableTreeNode) path.getLastPathComponent();
        ProtoNode n = (ProtoNode) dmt.getUserObject();

        JPopupMenu menu = new JPopupMenu();
        if (n.value != null) menu.add(item("Copy value", () -> copy(n.value)));
        menu.add(item("Copy as hex", () -> copy(hex(n.raw))));
        menu.add(item("Copy field path", () -> copy(pathOf(path))));
        if (n.isBytes() && n.raw.length > 0) {
            menu.addSeparator();
            JMenu as = new JMenu("Decode this field as");
            as.add(item("protobuf", () -> decodeInPlace(dmt, n, "protobuf")));
            as.add(item("gzip", () -> decodeInPlace(dmt, n, "gzip")));
            as.add(item("base64", () -> decodeInPlace(dmt, n, "base64")));
            as.add(item("utf-8 text", () -> decodeInPlace(dmt, n, "utf8")));
            menu.add(as);
        }
        menu.show(tree, e.getX(), e.getY());
    }

    private void decodeInPlace(DefaultMutableTreeNode dmt, ProtoNode n, String how) {
        try {
            byte[] b = n.raw;
            switch (how) {
                case "gzip":   b = Compression.gunzip(n.raw); break;
                case "base64": b = Base64.getMimeDecoder().decode(n.raw); break;
                case "utf8":   n.kind = ProtoNode.Kind.STRING; n.typeLabel = "str";
                               n.value = new String(n.raw, StandardCharsets.UTF_8);
                               n.children.clear(); refresh(dmt, n); return;
                default:       break; // protobuf: use raw as-is
            }
            reclassify(n, b);
            refresh(dmt, n);
        } catch (Exception ex) {
            Toolkit.getDefaultToolkit().beep();
        }
    }

    /** Turn a fresh byte[] into the best node kind (message / string / bytes). */
    private void reclassify(ProtoNode n, byte[] b) {
        n.raw = b;
        n.children.clear();
        String text = Protobuf.asPrintable(b);
        if (b.length > 0 && ProtobufStage.isProtobuf(b)) {
            n.kind = ProtoNode.Kind.MESSAGE; n.typeLabel = "msg"; n.value = null;
            n.children.addAll(ProtoNodes.parse(b, null).children);
        } else if (text != null) {
            n.kind = ProtoNode.Kind.STRING; n.typeLabel = "str"; n.value = text;
        } else {
            n.kind = ProtoNode.Kind.BYTES; n.typeLabel = "bytes"; n.value = b.length + " bytes";
        }
    }

    private void refresh(DefaultMutableTreeNode dmt, ProtoNode n) {
        build(dmt, n);
        model.nodeStructureChanged(dmt);
        tree.expandPath(new TreePath(dmt.getPath()));
    }

    private static String pathOf(TreePath path) {
        StringBuilder sb = new StringBuilder();
        Object[] a = path.getPath();
        for (Object o : a) {
            ProtoNode n = (ProtoNode) ((DefaultMutableTreeNode) o).getUserObject();
            if (n.kind == ProtoNode.Kind.ROOT) continue;
            if (sb.length() > 0) sb.append('.');
            sb.append(n.field);
        }
        return sb.toString();
    }

    private JMenuItem item(String text, Runnable r) {
        JMenuItem mi = new JMenuItem(text);
        mi.addActionListener(e -> r.run());
        return mi;
    }

    private static void copy(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s == null ? "" : s), null);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte value : b) sb.append(String.format("%02x", value & 0xff));
        return sb.toString();
    }

    // ---- renderer ----

    private final class Cell extends JPanel implements TreeCellRenderer {
        Cell() { super(new FlowLayout(FlowLayout.LEFT, 0, 0)); setOpaque(false); }

        @Override
        public Component getTreeCellRendererComponent(JTree t, Object value, boolean selected,
                boolean expanded, boolean leaf, int row, boolean hasFocus) {
            removeAll();
            setOpaque(selected);
            setBackground(sel);
            ProtoNode n = (ProtoNode) ((DefaultMutableTreeNode) value).getUserObject();
            if (n.kind == ProtoNode.Kind.ROOT) { add(seg("message", dim, false)); return this; }

            add(seg(n.field + " ", fnum, false));
            if (n.name != null) add(seg(n.name, fname, true));
            add(seg(" ", fg, false));

            switch (n.kind) {
                case MESSAGE:
                    add(seg(n.typeLabel + " ", type, false));
                    add(seg("{", brace, false));
                    break;
                case STRING:
                    add(seg("= ", brace, false));
                    add(seg('"' + trim(n.value, 200) + '"', str, false));
                    break;
                case VARINT: case I64: case I32:
                    add(seg("= ", brace, false));
                    add(seg(n.value, num, false));
                    if (n.typeLabel != null && n.typeLabel.length() > 6)
                        add(seg("  " + n.typeLabel.substring(7), dim, false)); // timestamp hint
                    break;
                case BYTES:
                    add(seg("‹bytes› ", bytes, false));
                    add(chip(n.value));
                    break;
                default: break;
            }
            return this;
        }

        private javax.swing.JLabel seg(String text, Color c, boolean bold) {
            javax.swing.JLabel l = new javax.swing.JLabel(text);
            l.putClientProperty("html.disable", Boolean.TRUE);
            l.setForeground(c);
            l.setFont(bold ? mono.deriveFont(Font.BOLD) : mono);
            return l;
        }

        private javax.swing.JLabel chip(String text) {
            javax.swing.JLabel l = new javax.swing.JLabel(" " + text + " ") {
                @Override protected void paintComponent(java.awt.Graphics g) {
                    java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
                    g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(chipBg); g2.fillRoundRect(0, 1, getWidth() - 1, getHeight() - 3, 8, 8);
                    g2.setColor(chipBd); g2.drawRoundRect(0, 1, getWidth() - 1, getHeight() - 3, 8, 8);
                    g2.dispose();
                    super.paintComponent(g);
                }
            };
            l.putClientProperty("html.disable", Boolean.TRUE);
            l.setForeground(dim);
            l.setFont(mono.deriveFont(11f));
            return l;
        }

        private String trim(String s, int n) { return s == null ? "" : (s.length() <= n ? s : s.substring(0, n) + "…"); }
    }

    public boolean isEmpty() { return ((DefaultMutableTreeNode) model.getRoot()).getChildCount() == 0; }
}
