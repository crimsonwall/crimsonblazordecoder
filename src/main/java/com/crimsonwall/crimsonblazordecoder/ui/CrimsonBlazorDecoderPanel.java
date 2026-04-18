/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for OWASP ZAP.
 *
 * Written by Renico Koen / Crimson Wall (crimsonwall.com) in 2026.
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
package com.crimsonwall.crimsonblazordecoder.ui;

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
import java.text.MessageFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.AbstractCellEditor;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import com.crimsonwall.crimsonblazordecoder.ExtensionCrimsonBlazorDecoder;
import com.crimsonwall.crimsonblazordecoder.decoder.BlazorPackMessage;
import com.crimsonwall.crimsonblazordecoder.regex.RegexConfig;
import com.crimsonwall.crimsonblazordecoder.regex.RegexEntry;

/**
 * Main UI panel for displaying decoded Blazor Pack messages.
 *
 * <p>This panel shows a table of all decoded messages on the left, with a detail view on the right
 * showing the pretty-printed JSON representation of the selected message.
 */
public class CrimsonBlazorDecoderPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;
    private static final String DATE_FORMAT_PATTERN = "HH:mm:ss.SSS";

    private ExtensionCrimsonBlazorDecoder extension;
    private MessageTableModel tableModel;
    private JTable messageTable;
    private JTextPane jsonView;
    private JTextPane rawView;
    private JTextArea modifyView;
    private JButton sendPacketButton;
    private JLabel modifyStatusLabel;
    private JPanel modifyPanel;
    private boolean modifyTabVisible = false;
    private JTabbedPane detailTabbedPane;
    private BlazorPackMessage currentMessage;
    private boolean autoSelect = true;
    private JButton clearButton;
    private JButton exportButton;
    private JLabel statusLabel;
    private volatile boolean sendInProgress = false;
    private final java.util.concurrent.ExecutorService sendExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor(
                    r -> {
                        Thread t = new Thread(r, "CrimsonBlazorDecoder-Send");
                        t.setDaemon(true);
                        return t;
                    });
    private final Set<Integer> markedRows = new HashSet<>();
    private final Set<Integer> regexMatchedRows = new HashSet<>();
    private final java.util.Map<Integer, java.util.Set<String>> regexMatchDetails = new java.util.HashMap<>();
    private static final Color COLOR_MARKED = new Color(50, 205, 50); // lime green
    private static final Color COLOR_REGEX_MATCH = Color.YELLOW;
    private static final int MAX_JSON_DISPLAY = 50000; // Max chars for JSON view
    private static final int MAX_HEX_DISPLAY_BYTES = 4096; // Max bytes for hex dump
    private static final int MAX_MESSAGES = 10000; // Max messages to keep in memory
    private static final int MAX_REGEX_RULES = 100; // Max regex rules allowed
    private static final int MAX_REGEX_INPUT = 5000; // Max chars of payload to match against
    private static final int MAX_REGEX_CHAR_ACCESSES = 100_000; // Character access budget per pattern
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern(DATE_FORMAT_PATTERN).withZone(ZoneId.systemDefault());

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
        setIcon(ExtensionCrimsonBlazorDecoder.getIcon());
    }

    /** Release resources held by this panel. Call during extension unload. */
    public void cleanup() {
        sendExecutor.shutdownNow();
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
        clearButton.setToolTipText(Constant.messages.getString("crimsonblazordecoder.button.clear.tooltip"));
        clearButton.addActionListener(new ClearButtonListener());
        buttonPanel.add(clearButton);

        exportButton =
                new JButton(Constant.messages.getString("crimsonblazordecoder.button.export"));
        exportButton.setToolTipText(Constant.messages.getString("crimsonblazordecoder.button.export.tooltip"));
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
        messageTable =
                new JTable(tableModel) {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public String getToolTipText(java.awt.event.MouseEvent event) {
                        int row = rowAtPoint(event.getPoint());
                        if (row < 0) return null;
                        int modelRow = convertRowIndexToModel(row);
                        java.util.Set<String> matches = regexMatchDetails.get(modelRow);
                        if (matches == null || matches.isEmpty()) return null;
                        return "Regex match: " + String.join(", ", matches);
                    }
                };
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
        JMenuItem markItem = new JMenuItem(Constant.messages.getString("crimsonblazordecoder.popup.mark"));
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
                            JMenuItem unmarkItem = new JMenuItem(
                                    Constant.messages.getString("crimsonblazordecoder.popup.unmark"));
                            unmarkItem.addActionListener(
                                    ev -> {
                                        markedRows.remove(modelRow);
                                        tableModel.fireTableRowsUpdated(row, row);
                                    });
                            popup.add(unmarkItem);
                        } else {
                            JMenuItem mark = new JMenuItem(
                                    Constant.messages.getString("crimsonblazordecoder.popup.mark"));
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
                            String text = getDocument().getText(0, getDocument().getLength());
                            // Find the line containing the offset
                            int ls = text.lastIndexOf('\n', offset) + 1;
                            int le = text.indexOf('\n', offset);
                            if (le == -1) le = text.length();
                            String line = text.substring(ls, le);
                            Matcher m = timestampPattern.matcher(line);
                            if (m.find()) {
                                long epoch = Long.parseLong(m.group(1));
                                DateTimeFormatter fullFormat =
                                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
                                                .withZone(ZoneId.systemDefault());
                                return (epoch + " = " + fullFormat.format(Instant.ofEpochMilli(epoch)))
                                        .replace("&", "&amp;")
                                        .replace("<", "&lt;")
                                        .replace(">", "&gt;");
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
        tabbedPane.setToolTipTextAt(0, Constant.messages.getString("crimsonblazordecoder.tab.json.tooltip"));

        // Modify tab — built but not added until an outgoing message is selected
        modifyPanel = createModifyPanel();

        // Raw hex view
        rawView = new JTextPane();
        rawView.setEditable(false);
        rawView.setBackground(COLOR_BG);
        rawView.setCaretColor(Color.WHITE);
        JScrollPane rawScroll = new JScrollPane(rawView);
        tabbedPane.addTab(Constant.messages.getString("crimsonblazordecoder.tab.raw"), rawScroll);
        tabbedPane.setToolTipTextAt(1, Constant.messages.getString("crimsonblazordecoder.tab.raw.tooltip"));

        addCopyPopup(jsonView);
        addCopyPopup(rawView);

        panel.add(tabbedPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createModifyPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        // Editable text area with matching dark theme
        modifyView = new JTextArea();
        modifyView.setFont(new Font("Monospaced", Font.PLAIN, 12));
        modifyView.setBackground(COLOR_BG);
        modifyView.setForeground(new Color(171, 178, 191));
        modifyView.setCaretColor(Color.WHITE);
        modifyView.setLineWrap(false);
        modifyView.setTabSize(2);
        JScrollPane modifyScroll = new JScrollPane(modifyView);
        panel.add(modifyScroll, BorderLayout.CENTER);

        // Bottom bar: status label + send button
        JPanel bottomBar = new JPanel();
        bottomBar.setLayout(new BoxLayout(bottomBar, BoxLayout.X_AXIS));
        bottomBar.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));

        modifyStatusLabel = new JLabel(" ");
        modifyStatusLabel.setFont(modifyStatusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        bottomBar.add(modifyStatusLabel);
        bottomBar.add(Box.createHorizontalGlue());

        sendPacketButton =
                new JButton(
                        Constant.messages.getString("crimsonblazordecoder.modify.button.send"));
        sendPacketButton.setToolTipText(
                Constant.messages.getString("crimsonblazordecoder.modify.button.send.tooltip"));
        sendPacketButton.setEnabled(false);
        sendPacketButton.addActionListener(new SendPacketButtonListener());
        bottomBar.add(sendPacketButton);

        panel.add(bottomBar, BorderLayout.SOUTH);

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
                    if (tableModel.getRowCount() >= MAX_MESSAGES) {
                        tableModel.removeOldest();
                    }
                    tableModel.addMessage(message);

                    // Check regex matches for the newly added row
                    int modelRow = tableModel.getRowCount() - 1;
                    java.util.Set<String> matches = findRegexMatches(message);
                    if (!matches.isEmpty()) {
                        regexMatchedRows.add(modelRow);
                        regexMatchDetails.put(modelRow, matches);
                    }

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
            updateModifyView(null);
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
        // Only highlight regex matches in the JSON text if the row is flagged as a match
        if (regexMatchedRows.contains(modelRow)) {
            highlightRegexMatches(json);
        }
        jsonView.setCaretPosition(0);

        highlightHexDump(currentMessage.getRawPayload());
        rawView.setCaretPosition(0);

        updateModifyView(currentMessage);
    }

    /** Show or hide the Modify tab and populate it based on the currently selected message. */
    private void updateModifyView(BlazorPackMessage message) {
        modifyStatusLabel.setText(" ");

        boolean shouldShow =
                message != null
                        && message.isOutgoing()
                        && message.getRawPayload() != null
                        && !message.getRawPayload().isEmpty();

        if (shouldShow && !modifyTabVisible) {
            detailTabbedPane.insertTab(
                    Constant.messages.getString("crimsonblazordecoder.tab.modify"),
                    null,
                    modifyPanel,
                    Constant.messages.getString("crimsonblazordecoder.tab.modify.tooltip"),
                    1);
            modifyTabVisible = true;
        } else if (!shouldShow && modifyTabVisible) {
            if (detailTabbedPane.getSelectedComponent() == modifyPanel) {
                detailTabbedPane.setSelectedIndex(0);
            }
            detailTabbedPane.remove(modifyPanel);
            modifyTabVisible = false;
        }

        if (!shouldShow) {
            modifyView.setText("");
            modifyView.setEditable(false);
            sendPacketButton.setEnabled(false);
            return;
        }

        modifyView.setForeground(new Color(171, 178, 191));
        modifyView.setText(prettyPrintJson(message.getRawPayload()));
        modifyView.setCaretPosition(0);
        modifyView.setEditable(extension.isChannelActive(message.getMessageId()));
        sendPacketButton.setEnabled(extension.isChannelActive(message.getMessageId()));
    }

    /**
     * Pretty-print a JSON string with 2-space indentation. No syntax colouring — just formatted
     * text suitable for the editable Modify tab.
     */
    private String prettyPrintJson(String json) {
        if (json == null || json.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        boolean escape = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (escape) {
                out.append(c);
                // Handle backslash-u-XXXX — consume all 4 hex digits as part of the escape sequence
                if (c == 'u' && i + 4 < json.length()) {
                    out.append(json, i + 1, i + 5);
                    i += 4;
                }
                escape = false;
                continue;
            }

            if (c == '\\' && inString) {
                out.append(c);
                escape = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                out.append(c);
                continue;
            }

            if (inString) {
                out.append(c);
                continue;
            }

            // Outside strings — format whitespace
            switch (c) {
                case '{':
                case '[':
                    out.append(c);
                    indent += 2;
                    out.append('\n');
                    out.append(" ".repeat(indent));
                    break;
                case '}':
                case ']':
                    indent = Math.max(0, indent - 2);
                    out.append('\n');
                    out.append(" ".repeat(indent));
                    out.append(c);
                    break;
                case ',':
                    out.append(c);
                    out.append('\n');
                    out.append(" ".repeat(indent));
                    break;
                case ':':
                    out.append(c);
                    out.append(' ');
                    break;
                default:
                    if (!Character.isWhitespace(c)) {
                        out.append(c);
                    }
                    break;
            }
        }
        return out.toString();
    }

    /**
     * Render JSON with syntax highlighting into the jsonView JTextPane.
     *
     * <p>Applies color to keys (red), string values (green), numbers (orange), booleans/null
     * (purple), and punctuation (gray). Batches consecutive same-type characters into a single
     * insertString call to avoid O(n^2) document updates.
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
        // Segment batch buffer: accumulate text of the same style, then flush
        StringBuilder segment = new StringBuilder(256);
        SimpleAttributeSet currentAttr = null;

        while (i < len) {
            char c = json.charAt(i);
            SimpleAttributeSet attr;
            int advance;

            // Whitespace
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                attr = attrPunct;
                advance = 1;
            }
            // Structural characters
            else if (c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',') {
                attr = attrPunct;
                advance = 1;
            }
            // String (could be key or value)
            else if (c == '"') {
                int start = i;
                i++; // skip opening quote
                while (i < len) {
                    char sc = json.charAt(i);
                    if (sc == '\\' && i + 1 < len) {
                        i += 2;
                    } else if (sc == '"') {
                        i++; // skip closing quote
                        break;
                    } else {
                        i++;
                    }
                }
                // Peek ahead to check if this string is a key
                boolean isKey = false;
                int peek = i;
                while (peek < len && json.charAt(peek) == ' ') {
                    peek++;
                }
                if (peek < len && json.charAt(peek) == ':') {
                    isKey = true;
                }
                attr = isKey ? attrKey : attrString;
                // Flush any pending segment with different style first
                if (currentAttr != null && currentAttr != attr && segment.length() > 0) {
                    appendText(doc, segment.toString(), currentAttr);
                    segment.setLength(0);
                }
                currentAttr = attr;
                segment.append(json, start, i);
                continue;
            }
            // Number
            else if (c == '-' || (c >= '0' && c <= '9')) {
                int start = i;
                while (i < len) {
                    char nc = json.charAt(i);
                    if (nc == '-' || nc == '+' || nc == '.'
                            || nc == 'e' || nc == 'E'
                            || (nc >= '0' && nc <= '9')) {
                        i++;
                    } else {
                        break;
                    }
                }
                attr = attrNumber;
                if (currentAttr != null && currentAttr != attr && segment.length() > 0) {
                    appendText(doc, segment.toString(), currentAttr);
                    segment.setLength(0);
                }
                currentAttr = attr;
                segment.append(json, start, i);
                continue;
            }
            // Boolean or null
            else if (json.startsWith("true", i)) {
                attr = attrBoolNull;
                if (currentAttr != null && currentAttr != attr && segment.length() > 0) {
                    appendText(doc, segment.toString(), currentAttr);
                    segment.setLength(0);
                }
                currentAttr = attr;
                segment.append("true");
                i += 4;
                continue;
            } else if (json.startsWith("false", i)) {
                attr = attrBoolNull;
                if (currentAttr != null && currentAttr != attr && segment.length() > 0) {
                    appendText(doc, segment.toString(), currentAttr);
                    segment.setLength(0);
                }
                currentAttr = attr;
                segment.append("false");
                i += 5;
                continue;
            } else if (json.startsWith("null", i)) {
                attr = attrBoolNull;
                if (currentAttr != null && currentAttr != attr && segment.length() > 0) {
                    appendText(doc, segment.toString(), currentAttr);
                    segment.setLength(0);
                }
                currentAttr = attr;
                segment.append("null");
                i += 4;
                continue;
            }
            // Fallback: single char
            else {
                attr = attrPunct;
                advance = 1;
            }

            // Batch: same style -> append to segment; different style -> flush and start new
            if (currentAttr != attr) {
                if (segment.length() > 0 && currentAttr != null) {
                    appendText(doc, segment.toString(), currentAttr);
                    segment.setLength(0);
                }
                currentAttr = attr;
            }
            segment.append(c);
            i += advance;
        }

        // Flush remaining
        if (segment.length() > 0 && currentAttr != null) {
            appendText(doc, segment.toString(), currentAttr);
        }
    }

    /** Install a right-click context menu with Copy on a JTextPane. */
    private void addCopyPopup(JTextPane textPane) {
        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem(Constant.messages.getString("crimsonblazordecoder.popup.copy"));
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

    /** Attribute set for regex match background highlight (yellow, preserves existing foreground). */
    private static final SimpleAttributeSet attrRegexHighlight = new SimpleAttributeSet();

    static {
        StyleConstants.setBackground(attrRegexHighlight, COLOR_REGEX_MATCH);
    }

    /**
     * Apply yellow background highlighting to regex matches in the displayed JSON.
     *
     * <p>Only matches within the structured {@code "data"} section are highlighted — metadata fields
     * ({@code timestamp}, {@code messageId}, {@code rawPayload}, etc.) are excluded to avoid false
     * positives (e.g., credit card regex matching epoch timestamps).
     */
    private void highlightRegexMatches(String displayedJson) {
        if (currentMessage == null) return;

        // Find the "data": { ... } section in the displayed JSON
        int dataKeyIdx = displayedJson.indexOf("\"data\":");
        if (dataKeyIdx < 0) return;
        int sectionStart = displayedJson.indexOf('{', dataKeyIdx);
        if (sectionStart < 0) return;
        int sectionEnd = findMatchingBrace(displayedJson, sectionStart);
        if (sectionEnd < 0) return;

        String dataSection = displayedJson.substring(sectionStart, sectionEnd + 1);

        StyledDocument doc = jsonView.getStyledDocument();
        boolean outgoing = currentMessage.isOutgoing();

        List<RegexEntry> entries = outgoing
            ? extension.getRegexConfig().getActiveC2SEntries()
            : extension.getRegexConfig().getActiveS2CEntries();

        for (RegexEntry entry : entries) {
            Pattern p = entry.getCompiledPattern();
            if (p == null) continue;

            try {
                CharSequence bounded = new BoundedCharSequence(dataSection, MAX_REGEX_CHAR_ACCESSES);
                Matcher m = p.matcher(bounded);
                while (m.find()) {
                    int start = sectionStart + m.start();
                    int end = sectionStart + m.end();
                    if (start >= 0 && end > start && end <= doc.getLength()) {
                        doc.setCharacterAttributes(start, end - start, attrRegexHighlight, false);
                    }
                }
            } catch (IllegalStateException e) {
                // Character budget exceeded — skip this pattern
            } catch (Exception e) {
                // Other errors — skip
            }
        }
    }

    /** Find the index of the closing brace that matches the opening brace at {@code openIdx}. */
    private static int findMatchingBrace(String text, int openIdx) {
        int depth = 0;
        boolean inString = false;
        boolean escape = false;
        for (int i = openIdx; i < text.length(); i++) {
            char c = text.charAt(i);
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\' && inString) {
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                continue;
            }
            if (inString) continue;
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
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
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

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

            // Hex columns
            StringBuilder hexBuf = new StringBuilder(50);
            for (int col = 0; col < bytesPerRow; col++) {
                if (col == 8) hexBuf.append(' ');
                int idx = rowOffset + col;
                if (idx < bytes.length) {
                    int b = bytes[idx] & 0xFF;
                    hexBuf.append(HEX_CHARS[(b >> 4) & 0x0F]);
                    hexBuf.append(HEX_CHARS[b & 0x0F]);
                    hexBuf.append(' ');
                } else {
                    hexBuf.append("   ");
                }
            }
            hexBuf.append(' ').append('|');
            appendText(doc, hexBuf.toString(), attrHex);

            // ASCII column
            StringBuilder asciiBuf = new StringBuilder(17);
            for (int col = 0; col < bytesPerRow; col++) {
                int idx = rowOffset + col;
                if (idx < bytes.length) {
                    int b = bytes[idx] & 0xFF;
                    asciiBuf.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
                } else {
                    asciiBuf.append(' ');
                }
            }
            asciiBuf.append('|').append('\n');
            appendText(doc, asciiBuf.toString(), attrAscii);
        }

        // Footer
        if (displayBytes < bytes.length) {
            appendText(doc, String.format(
                    "%n%d of %d bytes shown (truncated)%n", displayBytes, bytes.length), attrOffset);
        } else {
            appendText(doc, String.format("%n%d bytes total%n", bytes.length), attrOffset);
        }
    }

    /** Update the status label. */
    private void updateStatus() {
        statusLabel.setText(
                Constant.messages.getString(
                        "crimsonblazordecoder.status.messages", tableModel.getRowCount()));
    }

    /**
     * Check if a decoded message matches any active regex rule.
     *
     * <p>Safeguards against catastrophic backtracking:
     * <ul>
     *   <li>Input is truncated to {@link #MAX_REGEX_INPUT} characters</li>
     *   <li>Each pattern match is wrapped in a {@link BoundedCharSequence} that throws
     *       after {@link #MAX_REGEX_CHAR_ACCESSES} character reads</li>
     *   <li>Any exception from a single pattern is caught and skipped</li>
     * </ul>
     *
     * @return the set of matching rule names, or an empty set if none matched
     */
    private java.util.Set<String> findRegexMatches(BlazorPackMessage message) {
        java.util.Set<String> matched = new java.util.LinkedHashSet<>();
        String json = message.toDecodedJson();
        if (json == null || json.isEmpty()) {
            return matched;
        }

        // Truncate input to bound overall match cost
        if (json.length() > MAX_REGEX_INPUT) {
            json = json.substring(0, MAX_REGEX_INPUT);
        }

        boolean outgoing = message.isOutgoing();
        List<RegexEntry> entries = outgoing
            ? extension.getRegexConfig().getActiveC2SEntries()
            : extension.getRegexConfig().getActiveS2CEntries();

        for (RegexEntry entry : entries) {
            Pattern p = entry.getCompiledPattern();
            if (p == null) {
                continue;
            }
            try {
                CharSequence bounded =
                        new BoundedCharSequence(json, MAX_REGEX_CHAR_ACCESSES);
                if (p.matcher(bounded).find()) {
                    matched.add(entry.getName());
                }
            } catch (IllegalStateException e) {
                // Character access budget exceeded — pattern is too expensive, skip
            } catch (Exception e) {
                // Other regex errors (StackOverflowError, etc.) — skip
            }
        }
        return matched;
    }

    /**
     * A CharSequence wrapper that throws {@link IllegalStateException} after a configured number
     * of {@link #charAt} accesses. This prevents catastrophic backtracking in regex engines from
     * freezing the UI — once the budget is exhausted the match fails fast.
     */
    private static class BoundedCharSequence implements CharSequence {
        private final String delegate;
        private final java.util.concurrent.atomic.AtomicInteger remaining;

        BoundedCharSequence(String delegate, int accessLimit) {
            this.delegate = delegate;
            this.remaining = new java.util.concurrent.atomic.AtomicInteger(accessLimit);
        }

        private BoundedCharSequence(String delegate, java.util.concurrent.atomic.AtomicInteger accessBudget) {
            this.delegate = delegate;
            this.remaining = accessBudget;
        }

        @Override
        public int length() {
            return delegate.length();
        }

        @Override
        public char charAt(int index) {
            if (remaining.decrementAndGet() < 0) {
                throw new IllegalStateException("Regex character access limit exceeded");
            }
            return delegate.charAt(index);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new BoundedCharSequence(delegate.substring(start, end), remaining);
        }
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
                    return DATE_FORMAT.format(Instant.ofEpochMilli(message.getTimestamp()));
                case 1: // Type
                    return message.getMessageType().toString();
                case 2: // Direction
                    return message.isOutgoing()
                            ? Constant.messages.getString("crimsonblazordecoder.table.direction.c2s")
                            : Constant.messages.getString("crimsonblazordecoder.table.direction.s2c");
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

        public void removeOldest() {
            if (!messages.isEmpty()) {
                messages.remove(0);
                markedRows.remove(0);
                regexMatchedRows.remove(0);
                // Shift all marked indices down by 1
                Set<Integer> shifted = new HashSet<>();
                for (Integer idx : markedRows) {
                    shifted.add(idx - 1);
                }
                markedRows.clear();
                markedRows.addAll(shifted);
                Set<Integer> shiftedRegex = new HashSet<>();
                for (Integer idx : regexMatchedRows) {
                    shiftedRegex.add(idx - 1);
                }
                regexMatchedRows.clear();
                regexMatchedRows.addAll(shiftedRegex);
                java.util.Map<Integer, java.util.Set<String>> shiftedDetails = new java.util.HashMap<>();
                for (java.util.Map.Entry<Integer, java.util.Set<String>> e : regexMatchDetails.entrySet()) {
                    int key = e.getKey();
                    if (key == 0) continue; // removed row
                    shiftedDetails.put(key - 1, e.getValue());
                }
                regexMatchDetails.clear();
                regexMatchDetails.putAll(shiftedDetails);
                fireTableRowsDeleted(0, 0);
            }
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
        private final Color COLOR_RENDER_BATCH = new Color(200, 230, 255);
        private final Color COLOR_JS_INTEROP = new Color(200, 255, 200);
        private final Color COLOR_ERROR_BG = new Color(255, 200, 200);

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
                int modelRow = table.convertRowIndexToModel(row);

                // Apply base colors first: marked > type-based > default
                if (markedRows.contains(modelRow)) {
                    c.setBackground(COLOR_MARKED);
                } else {
                    BlazorPackMessage message = tableModel.getMessageAt(modelRow);

                    switch (message.getMessageType()) {
                        case RENDER_BATCH:
                            c.setBackground(COLOR_RENDER_BATCH);
                            break;
                        case JS_INTEROP:
                            c.setBackground(COLOR_JS_INTEROP);
                            break;
                        case ERROR:
                            c.setBackground(COLOR_ERROR_BG);
                            break;
                        default:
                            c.setBackground(Color.WHITE);
                    }
                }

                // Yellow regex highlight applied last — overrides all other colors
                if (regexMatchedRows.contains(modelRow)) {
                    c.setBackground(COLOR_REGEX_MATCH);
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
                autoSelect = true;
                markedRows.clear();
                regexMatchedRows.clear();
                regexMatchDetails.clear();
                currentMessage = null;
                updateStatus();
                jsonView.setText("");
                updateModifyView(null);
            }
        }
    }

    /** Action listener for the Send to Server button in the Modify tab. */
    private class SendPacketButtonListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            if (currentMessage == null || !currentMessage.isOutgoing()) {
                return;
            }

            String editedJson = modifyView.getText().trim();
            if (editedJson.isEmpty()) {
                modifyStatusLabel.setForeground(Color.RED);
                modifyStatusLabel.setText(
                        Constant.messages.getString(
                                "crimsonblazordecoder.modify.send.parseerror", "empty input"));
                return;
            }

            sendPacketButton.setEnabled(false);
            sendInProgress = true;
            modifyStatusLabel.setForeground(new Color(171, 178, 191));
            modifyStatusLabel.setText(
                    Constant.messages.getString("crimsonblazordecoder.modify.send.sending"));

            int channelId = currentMessage.getMessageId();
            boolean isBinary = currentMessage.isBinary();

            sendExecutor.submit(
                    () -> {
                        String statusText;
                        Color statusColor;
                        try {
                            extension.sendModifiedPacket(channelId, editedJson, isBinary);
                            statusText =
                                    Constant.messages.getString(
                                            "crimsonblazordecoder.modify.send.success");
                            statusColor = new Color(152, 195, 127); // green
                        } catch (IllegalStateException ex) {
                            statusText =
                                    Constant.messages.getString(
                                            "crimsonblazordecoder.modify.send.noconnection");
                            statusColor = Color.RED;
                        } catch (IllegalArgumentException ex) {
                            statusText =
                                    MessageFormat.format(
                                            Constant.messages.getString(
                                                    "crimsonblazordecoder.modify.send.parseerror"),
                                            ex.getMessage());
                            statusColor = Color.RED;
                        } catch (Exception ex) {
                            statusText =
                                    MessageFormat.format(
                                            Constant.messages.getString(
                                                    "crimsonblazordecoder.modify.send.error"),
                                            ex.getMessage());
                            statusColor = Color.RED;
                        }

                        final String finalStatus = statusText;
                        final Color finalColor = statusColor;
                        SwingUtilities.invokeLater(
                                () -> {
                                    modifyStatusLabel.setForeground(finalColor);
                                    modifyStatusLabel.setText(finalStatus);
                                    sendInProgress = false;
                                    sendPacketButton.setEnabled(true);
                                });
                    });
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
                        Constant.messages.getString("crimsonblazordecoder.export.dialog.title"),
                        JOptionPane.WARNING_MESSAGE);
                return;
            }

            int modelRow = messageTable.convertRowIndexToModel(selectedRow);
            BlazorPackMessage message = tableModel.getMessageAt(modelRow);
            boolean isJsonTab = detailTabbedPane.getSelectedIndex() == 0;

            javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
            String exportTitle = Constant.messages.getString("crimsonblazordecoder.export.dialog.title");
            if (isJsonTab) {
                fileChooser.setDialogTitle(
                        Constant.messages.getString("crimsonblazordecoder.export.json.title"));
                fileChooser.setSelectedFile(
                        new java.io.File(
                                "blazor_message_"
                                        + message.getMessageId()
                                        + "_"
                                        + message.getTimestamp()
                                        + ".json"));
                fileChooser.setFileFilter(
                        new javax.swing.filechooser.FileNameExtensionFilter(
                                Constant.messages.getString("crimsonblazordecoder.export.extension.json"),
                                "json"));
            } else {
                fileChooser.setDialogTitle(
                        Constant.messages.getString("crimsonblazordecoder.export.raw.title"));
                fileChooser.setSelectedFile(
                        new java.io.File(
                                "blazor_message_"
                                        + message.getMessageId()
                                        + "_"
                                        + message.getTimestamp()
                                        + ".raw"));
                fileChooser.setFileFilter(
                        new javax.swing.filechooser.FileNameExtensionFilter(
                                Constant.messages.getString("crimsonblazordecoder.export.extension.raw"),
                                "raw"));
            }

            int userSelection = fileChooser.showSaveDialog(CrimsonBlazorDecoderPanel.this);
            if (userSelection == javax.swing.JFileChooser.APPROVE_OPTION) {
                java.io.File file = fileChooser.getSelectedFile();

                // Confirm overwrite if file exists
                if (file.exists()) {
                    int overwrite = JOptionPane.showConfirmDialog(
                            CrimsonBlazorDecoderPanel.this,
                            Constant.messages.getString("crimsonblazordecoder.export.confirm.overwrite"),
                            Constant.messages.getString("crimsonblazordecoder.export.confirm.overwrite.title"),
                            JOptionPane.YES_NO_OPTION);
                    if (overwrite != JOptionPane.YES_OPTION) return;
                }

                if (isJsonTab) {
                    if (!file.getName().endsWith(".json")) {
                        file = new java.io.File(file.getAbsolutePath() + ".json");
                    }
                    try (java.io.OutputStreamWriter writer =
                            new java.io.OutputStreamWriter(
                                    new java.io.FileOutputStream(file),
                                    java.nio.charset.StandardCharsets.UTF_8)) {
                        writer.write(message.toPrettyJson());
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                MessageFormat.format(
                                        Constant.messages.getString("crimsonblazordecoder.export.success"),
                                        file.getName()),
                                exportTitle,
                                JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                MessageFormat.format(
                                        Constant.messages.getString("crimsonblazordecoder.export.failed"),
                                        ex.getMessage()),
                                Constant.messages.getString("crimsonblazordecoder.export.error.title"),
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
                                Constant.messages.getString("crimsonblazordecoder.export.norawdata"),
                                Constant.messages.getString("crimsonblazordecoder.export.error.title"),
                                JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
                        fos.write(rawBytes);
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                MessageFormat.format(
                                        Constant.messages.getString("crimsonblazordecoder.export.success"),
                                        file.getName()),
                                exportTitle,
                                JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(
                                CrimsonBlazorDecoderPanel.this,
                                MessageFormat.format(
                                        Constant.messages.getString("crimsonblazordecoder.export.failed"),
                                        ex.getMessage()),
                                Constant.messages.getString("crimsonblazordecoder.export.error.title"),
                                JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }
    }
}
