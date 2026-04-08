/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for OWASP ZAP.
 *
 * Written by Renico Koen. Published by crimsonwall.com in 2026.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.crimsonblazordecoder.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.addon.crimsonblazordecoder.ExtensionCrimsonBlazorDecoder;
import org.zaproxy.addon.crimsonblazordecoder.decoder.BlazorPackMessage;

/**
 * Main UI panel for displaying decoded Blazor Pack messages.
 *
 * <p>This panel shows a table of all decoded messages on the left, with a detail view on the right
 * showing the pretty-printed JSON representation of the selected message.
 */
public class CrimsonBlazorDecoderPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss.SSS");

    private ExtensionCrimsonBlazorDecoder extension;
    private MessageTableModel tableModel;
    private JTable messageTable;
    private JTextPane jsonView;
    private JTextPane rawView;
    private JTabbedPane detailTabbedPane;
    private BlazorPackMessage currentMessage;
    private boolean autoSelect = true;
    private JButton clearButton;
    private JButton exportButton;
    private JLabel statusLabel;
    private int messageCount = 0;
    private final Set<Integer> markedRows = new HashSet<>();
    private static final Color COLOR_MARKED = new Color(50, 205, 50); // lime green
    private static final int MAX_JSON_DISPLAY = 50000; // Max chars for JSON view
    private static final int MAX_HEX_DISPLAY_BYTES = 4096; // Max bytes for hex dump

    // JSON syntax highlighting colors (One Dark theme)
    private static final Color COLOR_KEY = new Color(224, 108, 117); // soft red
    private static final Color COLOR_STRING = new Color(152, 195, 127); // green
    private static final Color COLOR_NUMBER = new Color(209, 154, 102); // orange
    private static final Color COLOR_BOOL_NULL = new Color(198, 120, 221); // purple
    private static final Color COLOR_PUNCT = new Color(171, 178, 191); // light gray
    private static final Color COLOR_BG = new Color(40, 44, 52);

    private final SimpleAttributeSet attrKey = new SimpleAttributeSet();
    private final SimpleAttributeSet attrString = new SimpleAttributeSet();
    private final SimpleAttributeSet attrNumber = new SimpleAttributeSet();
    private final SimpleAttributeSet attrBoolNull = new SimpleAttributeSet();
    private final SimpleAttributeSet attrPunct = new SimpleAttributeSet();

    public CrimsonBlazorDecoderPanel(ExtensionCrimsonBlazorDecoder extension) {
        this.extension = extension;
        initAttributes();
        initialize();
    }

    private void initAttributes() {
        StyleConstants.setFontFamily(attrKey, "Monospaced");
        StyleConstants.setFontSize(attrKey, 12);
        StyleConstants.setForeground(attrKey, COLOR_KEY);

        StyleConstants.setFontFamily(attrString, "Monospaced");
        StyleConstants.setFontSize(attrString, 12);
        StyleConstants.setForeground(attrString, COLOR_STRING);

        StyleConstants.setFontFamily(attrNumber, "Monospaced");
        StyleConstants.setFontSize(attrNumber, 12);
        StyleConstants.setForeground(attrNumber, COLOR_NUMBER);

        StyleConstants.setFontFamily(attrBoolNull, "Monospaced");
        StyleConstants.setFontSize(attrBoolNull, 12);
        StyleConstants.setForeground(attrBoolNull, COLOR_BOOL_NULL);

        StyleConstants.setFontFamily(attrPunct, "Monospaced");
        StyleConstants.setFontSize(attrPunct, 12);
        StyleConstants.setForeground(attrPunct, COLOR_PUNCT);
    }

    private void initialize() {
        setLayout(new BorderLayout());
        setName(Constant.messages.getString("crimsonblazordecoder.panel.title"));

        // Create top toolbar
        JPanel toolbar = createToolbar();
        add(toolbar, BorderLayout.NORTH);

        // Create main split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(400);
        splitPane.setResizeWeight(0.4);

        // Left side - message list
        JPanel listPanel = createMessageListPanel();
        splitPane.setLeftComponent(listPanel);

        // Right side - JSON detail view
        JPanel detailPanel = createDetailPanel();
        splitPane.setRightComponent(detailPanel);

        add(splitPane, BorderLayout.CENTER);

        // Create status bar
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);
    }

    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());

        JLabel titleLabel = new JLabel(getName());
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        toolbar.add(titleLabel, BorderLayout.WEST);

        JPanel buttonPanel = new JPanel();
        clearButton = new JButton(Constant.messages.getString("crimsonblazordecoder.button.clear"));
        clearButton.addActionListener(new ClearButtonListener());
        buttonPanel.add(clearButton);

        exportButton =
                new JButton(Constant.messages.getString("crimsonblazordecoder.button.export"));
        exportButton.addActionListener(new ExportButtonListener());
        buttonPanel.add(exportButton);

        toolbar.add(buttonPanel, BorderLayout.EAST);

        return toolbar;
    }

    private JPanel createMessageListPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JLabel label = new JLabel(Constant.messages.getString("crimsonblazordecoder.list.label"));
        label.setBorder(javax.swing.BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(label, BorderLayout.NORTH);

        tableModel = new MessageTableModel();
        messageTable = new JTable(tableModel);
        messageTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        messageTable.setAutoCreateRowSorter(true);
        messageTable.setDefaultRenderer(Object.class, new MessageTableCellRenderer());
        messageTable
                .getSelectionModel()
                .addListSelectionListener(
                        e -> {
                            if (!e.getValueIsAdjusting()) {
                                // Detect if user manually selected a row
                                int selectedRow = messageTable.getSelectedRow();
                                if (selectedRow >= 0) {
                                    int lastRow = messageTable.getRowCount() - 1;
                                    if (selectedRow == lastRow) {
                                        // User selected the last row - re-enable auto-select
                                        autoSelect = true;
                                    } else {
                                        // User selected a non-last row - disable auto-select
                                        autoSelect = false;
                                    }
                                }
                                updateDetailView();
                            }
                        });

        JScrollPane scrollPane = new JScrollPane(messageTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        addTablePopupMenu();

        return panel;
    }

    private void addTablePopupMenu() {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem markItem = new JMenuItem("Mark");
        popup.add(markItem);

        messageTable.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {
                        showPopup(e);
                    }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        showPopup(e);
                    }

                    private void showPopup(MouseEvent e) {
                        if (!e.isPopupTrigger()) return;
                        int row = messageTable.rowAtPoint(e.getPoint());
                        if (row < 0) return;

                        // Select the row under the cursor
                        messageTable.setRowSelectionInterval(row, row);
                        int modelRow = messageTable.convertRowIndexToModel(row);
                        boolean isMarked = markedRows.contains(modelRow);

                        popup.removeAll();
                        if (isMarked) {
                            JMenuItem unmarkItem = new JMenuItem("Unmark");
                            unmarkItem.addActionListener(
                                    ev -> {
                                        markedRows.remove(modelRow);
                                        tableModel.fireTableRowsUpdated(row, row);
                                    });
                            popup.add(unmarkItem);
                        } else {
                            JMenuItem mark = new JMenuItem("Mark");
                            mark.addActionListener(
                                    ev -> {
                                        markedRows.add(modelRow);
                                        tableModel.fireTableRowsUpdated(row, row);
                                    });
                            popup.add(mark);
                        }
                        popup.show(e.getComponent(), e.getX(), e.getY());
                    }
                });
    }

    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();
        detailTabbedPane = tabbedPane;

        // JSON view with syntax highlighting and timestamp tooltips
        jsonView =
                new JTextPane() {
                    private static final long serialVersionUID = 1L;
                    private final Pattern timestampPattern =
                            Pattern.compile("\"timestamp\"\\s*:\\s*(\\d+)");

                    @Override
                    public String getToolTipText(java.awt.event.MouseEvent event) {
                        if (currentMessage == null) {
                            return null;
                        }
                        // Check if mouse is near the timestamp field
                        int offset = viewToModel(event.getPoint());
                        try {
                            int lineStart = 0;
                            String text = getDocument().getText(0, getDocument().getLength());
                            // Find the line containing the offset
                            int ls = text.lastIndexOf('\n', offset) + 1;
                            int le = text.indexOf('\n', offset);
                            if (le == -1) le = text.length();
                            String line = text.substring(ls, le);
                            Matcher m = timestampPattern.matcher(line);
                            if (m.find()) {
                                long epoch = Long.parseLong(m.group(1));
                                Date date = new Date(epoch);
                                SimpleDateFormat fullFormat =
                                        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
                                return epoch + " = " + fullFormat.format(date);
                            }
                        } catch (Exception e) {
                            // ignore
                        }
                        return null;
                    }
                };
        jsonView.setEditable(false);
        jsonView.setBackground(COLOR_BG);
        jsonView.setCaretColor(Color.WHITE);
        JScrollPane jsonScroll = new JScrollPane(jsonView);
        tabbedPane.addTab(Constant.messages.getString("crimsonblazordecoder.tab.json"), jsonScroll);

        // Raw hex view
        rawView = new JTextPane();
        rawView.setEditable(false);
        rawView.setBackground(COLOR_BG);
        rawView.setCaretColor(Color.WHITE);
        JScrollPane rawScroll = new JScrollPane(rawView);
        tabbedPane.addTab(Constant.messages.getString("crimsonblazordecoder.tab.raw"), rawScroll);

        addCopyPopup(jsonView);
        addCopyPopup(rawView);

        panel.add(tabbedPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createStatusBar() {
        JPanel panel = new JPanel(new BorderLayout());
        statusLabel = new JLabel(Constant.messages.getString("crimsonblazordecoder.status.ready"));
        statusLabel.setBorder(javax.swing.BorderFactory.createEmptyBorder(2, 5, 2, 5));
        panel.add(statusLabel, BorderLayout.WEST);
        return panel;
    }

    /** Add a decoded message to the panel. */
    public void addMessage(BlazorPackMessage message) {
        SwingUtilities.invokeLater(
                () -> {
                    tableModel.addMessage(message);
                    messageCount++;
                    updateStatus();

                    if (autoSelect) {
                        int lastRow = messageTable.getRowCount() - 1;
                        messageTable.setRowSelectionInterval(lastRow, lastRow);
                        messageTable.scrollRectToVisible(
                                messageTable.getCellRect(lastRow, 0, true));
                    }
                });
    }

    /** Update the detail view based on selected message. */
    private void updateDetailView() {
        int selectedRow = messageTable.getSelectedRow();
        if (selectedRow < 0) {
            currentMessage = null;
            jsonView.setText("");
            rawView.setText("");
            return;
        }

        int modelRow = messageTable.convertRowIndexToModel(selectedRow);
        currentMessage = tableModel.getMessageAt(modelRow);

        String json = currentMessage.toPrettyJson();
        if (json.length() > MAX_JSON_DISPLAY) {
            json =
                    json.substring(0, MAX_JSON_DISPLAY)
                            + "\n  // ... truncated ("
                            + json.length()
                            + " chars total)";
        }
        highlightJson(json);
        jsonView.setCaretPosition(0);

        highlightHexDump(currentMessage.getRawPayload());
        rawView.setCaretPosition(0);
    }

    /**
     * Render JSON with syntax highlighting into the jsonView JTextPane.
     *
     * <p>Applies color to keys (red), string values (green), numbers (orange), booleans/null
     * (purple), and punctuation (gray).
     */
    private void highlightJson(String json) {
        StyledDocument doc = jsonView.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
        } catch (Exception e) {
            return;
        }

        if (json == null || json.isEmpty()) {
            return;
        }

        int i = 0;
        int len = json.length();

        while (i < len) {
            char c = json.charAt(i);

            // Whitespace
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                appendText(doc, String.valueOf(c), attrPunct);
                i++;
                continue;
            }

            // Structural characters
            if (c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',') {
                appendText(doc, String.valueOf(c), attrPunct);
                i++;
                continue;
            }

            // String (could be key or value)
            if (c == '"') {
                i++; // skip opening quote
                StringBuilder sb = new StringBuilder();
                while (i < len) {
                    char sc = json.charAt(i);
                    if (sc == '\\' && i + 1 < len) {
                        sb.append(sc);
                        sb.append(json.charAt(i + 1));
                        i += 2;
                    } else if (sc == '"') {
                        i++; // skip closing quote
                        break;
                    } else {
                        sb.append(sc);
                        i++;
                    }
                }
                String content = "\"" + sb.toString() + "\"";

                // A key is followed by ':'
                boolean isKey = false;
                int peek = i;
                while (peek < len && json.charAt(peek) == ' ') {
                    peek++;
                }
                if (peek < len && json.charAt(peek) == ':') {
                    isKey = true;
                }

                appendText(doc, content, isKey ? attrKey : attrString);
                continue;
            }

            // Number
            if (c == '-' || (c >= '0' && c <= '9')) {
                StringBuilder sb = new StringBuilder();
                while (i < len) {
                    char nc = json.charAt(i);
                    if (nc == '-'
                            || nc == '+'
                            || nc == '.'
                            || nc == 'e'
                            || nc == 'E'
                            || (nc >= '0' && nc <= '9')) {
                        sb.append(nc);
                        i++;
                    } else {
                        break;
                    }
                }
                appendText(doc, sb.toString(), attrNumber);
                continue;
            }

            // Boolean or null
            if (json.startsWith("true", i)) {
                appendText(doc, "true", attrBoolNull);
                i += 4;
                continue;
            }
            if (json.startsWith("false", i)) {
                appendText(doc, "false", attrBoolNull);
                i += 5;
                continue;
            }
            if (json.startsWith("null", i)) {
                appendText(doc, "null", attrBoolNull);
                i += 4;
                continue;
            }

            // Fallback: single char
            appendText(doc, String.valueOf(c), attrPunct);
            i++;
        }
    }

    /** Install a right-click context menu with Copy on a JTextPane. */
    private void addCopyPopup(JTextPane textPane) {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy");
        copyItem.addActionListener(
                e -> {
                    String selected = textPane.getSelectedText();
                    if (selected != null && !selected.isEmpty()) {
                        Toolkit.getDefaultToolkit()
                                .getSystemClipboard()
                                .setContents(new StringSelection(selected), null);
                    }
                });
        popup.add(copyItem);

        textPane.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {
                        showPopup(e);
                    }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        showPopup(e);
                    }

                    private void showPopup(MouseEvent e) {
                        if (e.isPopupTrigger()) {
                            copyItem.setEnabled(
                                    textPane.getSelectedText() != null
                                            && !textPane.getSelectedText().isEmpty());
                            popup.show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                });
    }

    private void appendText(StyledDocument doc, String text, SimpleAttributeSet attr) {
        try {
            doc.insertString(doc.getLength(), text, attr);
        } catch (Exception e) {
            // ignore
        }
    }

    // Hex dump attribute sets
    private final SimpleAttributeSet attrOffset = new SimpleAttributeSet();
    private final SimpleAttributeSet attrHex = new SimpleAttributeSet();
    private final SimpleAttributeSet attrAscii = new SimpleAttributeSet();
    private final SimpleAttributeSet attrSeparator = new SimpleAttributeSet();

    private static final Color COLOR_OFFSET = new Color(92, 99, 112); // dim gray
    private static final Color COLOR_HEX = new Color(152, 195, 127); // green
    private static final Color COLOR_ASCII = new Color(97, 175, 239); // blue
    private static final Color COLOR_SEP = new Color(92, 99, 112); // dim gray

    {
        StyleConstants.setFontFamily(attrOffset, "Monospaced");
        StyleConstants.setFontSize(attrOffset, 12);
        StyleConstants.setForeground(attrOffset, COLOR_OFFSET);

        StyleConstants.setFontFamily(attrHex, "Monospaced");
        StyleConstants.setFontSize(attrHex, 12);
        StyleConstants.setForeground(attrHex, COLOR_HEX);

        StyleConstants.setFontFamily(attrAscii, "Monospaced");
        StyleConstants.setFontSize(attrAscii, 12);
        StyleConstants.setForeground(attrAscii, COLOR_ASCII);

        StyleConstants.setFontFamily(attrSeparator, "Monospaced");
        StyleConstants.setFontSize(attrSeparator, 12);
        StyleConstants.setForeground(attrSeparator, COLOR_SEP);
    }

    /** Render a hex dump with offset, hex bytes, and ASCII columns into the rawView pane. */
    private void highlightHexDump(String rawPayload) {
        StyledDocument doc = rawView.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
        } catch (Exception e) {
            return;
        }

        // Get the raw bytes from the stored field on the message
        int selectedRow = messageTable.getSelectedRow();
        if (selectedRow < 0) return;
        int modelRow = messageTable.convertRowIndexToModel(selectedRow);
        BlazorPackMessage message = tableModel.getMessageAt(modelRow);
        byte[] bytes = message.getRawBytes();

        if (bytes == null || bytes.length == 0) {
            // Fall back to rawPayload string if no bytes stored
            if (rawPayload != null && !rawPayload.isEmpty()) {
                appendText(doc, rawPayload, attrHex);
            }
            return;
        }

        int bytesPerRow = 16;
        int displayBytes = Math.min(bytes.length, MAX_HEX_DISPLAY_BYTES);
        int totalRows = (displayBytes + bytesPerRow - 1) / bytesPerRow;

        for (int row = 0; row < totalRows; row++) {
            int rowOffset = row * bytesPerRow;

            // Offset column
            appendText(doc, String.format("%08x  ", rowOffset), attrOffset);

            // Hex columns (two groups of 8)
            StringBuilder leftHex = new StringBuilder();
            StringBuilder rightHex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();

            for (int col = 0; col < bytesPerRow; col++) {
                int idx = rowOffset + col;
                if (col == 8) {
                    leftHex.append(" ");
                }
                if (idx < bytes.length) {
                    String hexByte = String.format("%02x", bytes[idx] & 0xFF);
                    if (col < 8) {
                        leftHex.append(hexByte).append(" ");
                    } else {
                        rightHex.append(hexByte).append(" ");
                    }
                    char c = (char) (bytes[idx] & 0xFF);
                    ascii.append(c >= 0x20 && c < 0x7f ? c : '.');
                } else {
                    if (col < 8) {
                        leftHex.append("   ");
                    } else {
                        rightHex.append("   ");
                    }
                    ascii.append(' ');
                }
            }

            appendText(doc, leftHex.toString(), attrHex);
            appendText(doc, " ", attrSeparator);
            appendText(doc, rightHex.toString(), attrHex);
            appendText(doc, " |", attrSeparator);
            appendText(doc, ascii.toString(), attrAscii);
            appendText(doc, "|\n", attrSeparator);
        }

        // Footer with total length
        if (displayBytes < bytes.length) {
            appendText(
                    doc,
                    String.format(
                            "%n%d of %d bytes shown (truncated)%n", displayBytes, bytes.length),
                    attrOffset);
        } else {
            appendText(doc, String.format("%n%d bytes total%n", bytes.length), attrOffset);
        }
    }

    /** Update the status label. */
    private void updateStatus() {
        statusLabel.setText(
                Constant.messages.getString("crimsonblazordecoder.status.messages", messageCount));
    }

    /** Table model for Blazor Pack messages. */
    @SuppressWarnings("serial")
    private class MessageTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private java.util.List<BlazorPackMessage> messages = new java.util.ArrayList<>();

        private final String[] columnNames = {
            Constant.messages.getString("crimsonblazordecoder.table.time"),
            Constant.messages.getString("crimsonblazordecoder.table.type"),
            Constant.messages.getString("crimsonblazordecoder.table.direction"),
            Constant.messages.getString("crimsonblazordecoder.table.summary")
        };

        @Override
        public int getRowCount() {
            return messages.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            BlazorPackMessage message = messages.get(rowIndex);

            switch (columnIndex) {
                case 0: // Time
                    return DATE_FORMAT.format(new Date(message.getTimestamp()));
                case 1: // Type
                    return message.getMessageType().toString();
                case 2: // Direction
                    return message.isOutgoing() ? "Client -> Server" : "Server -> Client";
                case 3: // Summary
                    return getSummary(message);
                default:
                    return "";
            }
        }

        private String getSummary(BlazorPackMessage message) {
            if (message.getDecodedData().containsKey("method")) {
                return "Method: " + message.getDecodedData().get("method");
            }
            switch (message.getMessageType()) {
                case PROTOCOL_HANDSHAKE:
                    return "Handshake";
                case RENDER_BATCH:
                    return "Render Batch";
                case CIRCUIT_START:
                    return "Start Circuit";
                case CIRCUIT_CLOSE:
                    return "Circuit Close";
                case JS_INTEROP:
                    return "JS Interop";
                case ERROR:
                    return "Error";
                default:
                    break;
            }
            if (message.getRawPayload() != null) {
                String payload = message.getRawPayload();
                if (payload.length() > 50) {
                    return payload.substring(0, 50) + "...";
                }
                return payload;
            }
            return "Unknown";
        }

        public void addMessage(BlazorPackMessage message) {
            messages.add(message);
            fireTableRowsInserted(messages.size() - 1, messages.size() - 1);
        }

        public BlazorPackMessage getMessageAt(int row) {
            return messages.get(row);
        }

        public void clear() {
            messages.clear();
            fireTableDataChanged();
        }
    }

    /** Custom cell renderer for the message table. */
    private class MessageTableCellRenderer extends DefaultTableCellRenderer {

        private static final long serialVersionUID = 1L;

        @Override
        public Component getTableCellRendererComponent(
                JTable table,
                Object value,
                boolean isSelected,
                boolean hasFocus,
                int row,
                int column) {

            Component c =
                    super.getTableCellRendererComponent(
                            table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                // Color code by message type
                int modelRow = table.convertRowIndexToModel(row);

                // Marked rows take priority
                if (markedRows.contains(modelRow)) {
                    c.setBackground(COLOR_MARKED);
                } else {
                    BlazorPackMessage message = tableModel.getMessageAt(modelRow);

                    switch (message.getMessageType()) {
                        case RENDER_BATCH:
                            c.setBackground(new Color(200, 230, 255));
                            break;
                        case JS_INTEROP:
                            c.setBackground(new Color(200, 255, 200));
                            break;
                        case ERROR:
                            c.setBackground(new Color(255, 200, 200));
                            break;
                        default:
                            c.setBackground(Color.WHITE);
                    }
                }
            }

            setHorizontalAlignment(column == 3 ? SwingConstants.LEFT : SwingConstants.CENTER);

            return c;
        }
    }

    /** Action listener for the clear button. */
    private class ClearButtonListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            int confirm =
                    JOptionPane.showConfirmDialog(
                            CrimsonBlazorDecoderPanel.this,
                            Constant.messages.getString("crimsonblazordecoder.confirm.clear"),
                            Constant.messages.getString("crimsonblazordecoder.confirm.clear.title"),
                            JOptionPane.YES_NO_OPTION);

            if (confirm == JOptionPane.YES_OPTION) {
                tableModel.clear();
                messageCount = 0;
                autoSelect = true;
                markedRows.clear();
                updateStatus();
                jsonView.setText("");
            }
        }
    }

    /** Action listener for the export button. */
    private class ExportButtonListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            int selectedRow = messageTable.getSelectedRow();
            if (selectedRow < 0) {
                JOptionPane.showMessageDialog(
                        CrimsonBlazorDecoderPanel.this,
                        Constant.messages.getString("crimsonblazordecoder.export.noselection"),
                        "Export",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }

            int modelRow = messageTable.convertRowIndexToModel(selectedRow);
            BlazorPackMessage message = tableModel.getMessageAt(modelRow);
            boolean isJsonTab = detailTabbedPane.getSelectedIndex() == 0;

            javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
            if (isJsonTab) {
                fileChooser.setDialogTitle("Export Message as JSON");
                fileChooser.setSelectedFile(
                        new java.io.File(
                                "blazor_message_"
                                        + message.getMessageId()
                                        + "_"
                                        + message.getTimestamp()
                                        + ".json"));
                fileChooser.setFileFilter(
                        new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));
            } else {
                fileChooser.setDialogTitle("Export Raw Binary Data");
                fileChooser.setSelectedFile(
                        new java.io.File(
                                "blazor_message_"
                                        + message.getMessageId()
                                        + "_"
                                        + message.getTimestamp()
                                        + ".raw"));
                fileChooser.setFileFilter(
                        new javax.swing.filechooser.FileNameExtensionFilter(
                                "Raw binary files", "raw"));
            }

            int userSelection = fileChooser.showSaveDialog(CrimsonBlazorDecoderPanel.this);
            if (userSelection == javax.swing.JFileChooser.APPROVE_OPTION) {
                java.io.File file = fileChooser.getSelectedFile();

                if (isJsonTab) {
                    if (!file.getName().endsWith(".json")) {
                        file = new java.io.File(file.getAbsolutePath() + ".json");
                    }
                    try (java.io.FileWriter writer = new java.io.FileWriter(file)) {
                        writer.write(message.toPrettyJson());
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                "Message exported to " + file.getName(),
                                "Export",
                                JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                "Export failed: " + ex.getMessage(),
                                "Export Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    if (!file.getName().endsWith(".raw")) {
                        file = new java.io.File(file.getAbsolutePath() + ".raw");
                    }
                    byte[] rawBytes = message.getRawBytes();
                    if (rawBytes == null) {
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                "No raw binary data available for this message",
                                "Export Error",
                                JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
                        fos.write(rawBytes);
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                "Raw data exported to " + file.getName(),
                                "Export",
                                JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                "Export failed: " + ex.getMessage(),
                                "Export Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }
    }
}
