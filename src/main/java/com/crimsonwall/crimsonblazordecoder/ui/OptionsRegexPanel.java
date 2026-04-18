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

import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.AbstractCellEditor;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamPanel;
import com.crimsonwall.crimsonblazordecoder.ExtensionCrimsonBlazorDecoder;
import com.crimsonwall.crimsonblazordecoder.regex.RegexEntry;

/**
 * Options panel for the Crimson Blazor Decoder add-on, registered under ZAP's Tools &rarr; Options dialog.
 *
 * <p>Provides a table of regex rules with name, pattern, client-to-server (C2S), and server-to-client (S2C)
 * columns for managing pattern matching rules that highlight sensitive data in decoded Blazor messages.
 */
public class OptionsRegexPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private static final int MAX_REGEX_RULES = 200;

    private final ExtensionCrimsonBlazorDecoder extension;

    private RegexTableModel tableModel;
    private JTable regexTable;

    public OptionsRegexPanel(ExtensionCrimsonBlazorDecoder extension) {
        this.extension = extension;
        setName(Constant.messages.getString("crimsonblazordecoder.options.title"));
        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(4, 4, 4, 4);

        JPanel tablePanel = createTablePanel();
        add(tablePanel, gbc);
    }

    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                Constant.messages.getString("crimsonblazordecoder.options.regex.title")));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(4, 4, 4, 4);

        tableModel = new RegexTableModel();
        regexTable = new JTable(tableModel) {
            private static final long serialVersionUID = 1L;

            @Override
            public Class<?> getColumnClass(int column) {
                switch (column) {
                    case 0: return String.class;
                    case 1: return String.class;
                    case 2: return Boolean.class;
                    case 3: return Boolean.class;
                    default: return Object.class;
                }
            }
        };
        regexTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        regexTable.setDefaultEditor(String.class, new RegexCellEditor());
        regexTable.setDefaultRenderer(Boolean.class, new CheckboxRenderer());
        regexTable.setDefaultEditor(Boolean.class, new CheckboxEditor());
        regexTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        regexTable.getColumnModel().getColumn(1).setPreferredWidth(350);
        regexTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        regexTable.getColumnModel().getColumn(3).setPreferredWidth(60);

        // Toggle all enabled checkboxes when clicking the "C->S" or "S->C" headers
        regexTable.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = regexTable.columnAtPoint(e.getPoint());
                if (col != 2 && col != 3) return;

                boolean newValue = false;
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    if (!(Boolean) tableModel.getValueAt(i, col)) {
                        newValue = true;
                        break;
                    }
                }
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    tableModel.setValueAt(newValue, i, col);
                }
            }
        });

        JScrollPane scroll = new JScrollPane(regexTable);
        panel.add(scroll, gbc);

        // Toolbar: Add / Remove buttons
        gbc.gridy = 1;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.X_AXIS));

        JButton addButton =
                new JButton(Constant.messages.getString("crimsonblazordecoder.options.regex.button.add"));
        addButton.setToolTipText(
                Constant.messages.getString("crimsonblazordecoder.options.regex.button.add.tooltip"));
        addButton.addActionListener(e -> {
            String[] result = showAddDialog();
            if (result != null) {
                tableModel.addEntry(new RegexEntry(result[0], result[1],
                        Boolean.parseBoolean(result[2]), Boolean.parseBoolean(result[3])));
                updateConfigFromTable();
            }
        });
        toolbar.add(addButton);
        toolbar.add(Box.createHorizontalStrut(4));

        JButton removeButton =
                new JButton(Constant.messages.getString("crimsonblazordecoder.options.regex.button.remove"));
        removeButton.setToolTipText(
                Constant.messages.getString("crimsonblazordecoder.options.regex.button.remove.tooltip"));
        removeButton.addActionListener(e -> {
            int row = regexTable.getSelectedRow();
            if (row >= 0) {
                tableModel.removeEntry(row);
                updateConfigFromTable();
            }
        });
        toolbar.add(removeButton);

        panel.add(toolbar, gbc);

        return panel;
    }

    /** Show a dialog to add a new regex rule. Returns [name, pattern, activeC2S, activeS2C] or null. */
    private String[] showAddDialog() {
        JTextField nameField = new JTextField(20);
        JTextField regexField = new JTextField(40);
        JCheckBox c2sCheckBox = new JCheckBox("Client -> Server");
        JCheckBox s2cCheckBox = new JCheckBox("Server -> Client");
        c2sCheckBox.setSelected(true);
        s2cCheckBox.setSelected(true);

        JPanel dialogPanel = new JPanel(new GridBagLayout());
        GridBagConstraints dc = new GridBagConstraints();
        dc.fill = GridBagConstraints.HORIZONTAL;
        dc.anchor = GridBagConstraints.WEST;

        dc.gridx = 0;
        dc.gridy = 0;
        dc.insets = new Insets(4, 4, 4, 4);
        JLabel nameLabel = new JLabel(
                Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.name"));
        nameLabel.setLabelFor(nameField);
        dialogPanel.add(nameLabel, dc);

        dc.gridx = 1;
        dc.weightx = 1.0;
        dialogPanel.add(nameField, dc);

        dc.gridx = 0;
        dc.gridy = 1;
        dc.weightx = 0.0;
        JLabel regexLabel = new JLabel(
                Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.regex"));
        regexLabel.setLabelFor(regexField);
        dialogPanel.add(regexLabel, dc);

        dc.gridx = 1;
        dc.weightx = 1.0;
        dialogPanel.add(regexField, dc);

        dc.gridx = 0;
        dc.gridy = 2;
        dc.gridwidth = 2;
        dialogPanel.add(c2sCheckBox, dc);

        dc.gridy = 3;
        dialogPanel.add(s2cCheckBox, dc);

        int result = JOptionPane.showConfirmDialog(
                this,
                dialogPanel,
                Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.title"),
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String regex = regexField.getText().trim();
            if (!name.isEmpty() && !regex.isEmpty()) {
                try {
                    Pattern.compile(regex);
                } catch (PatternSyntaxException ex) {
                    JOptionPane.showMessageDialog(
                            this,
                            Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.invalid")
                                    + " " + ex.getMessage(),
                            Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.error"),
                            JOptionPane.WARNING_MESSAGE);
                    return null;
                }
                return new String[]{name, regex,
                    String.valueOf(c2sCheckBox.isSelected()),
                    String.valueOf(s2cCheckBox.isSelected())};
            }
        }
        return null;
    }

    /** Update the in-memory config from the table (no disk write). */
    private void updateConfigFromTable() {
        extension.getRegexConfig().setEntries(new ArrayList<>(tableModel.getEntries()));
    }

    // --- AbstractParamPanel lifecycle ---

    @Override
    public void initParam(Object obj) {
        tableModel.setEntries(extension.getRegexConfig().getEntries());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        extension.getRegexConfig().setEntries(new ArrayList<>(tableModel.getEntries()));
        extension.getRegexConfig().save();
    }

    @Override
    public String getHelpIndex() {
        return "crimsonblazordecoder.options";
    }

    // --- Inner classes: table model, renderers, editors ---

    /** Table model for regex rules. */
    @SuppressWarnings("serial")
    private class RegexTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;

        private final String[] columnNames = {
            Constant.messages.getString("crimsonblazordecoder.options.regex.col.name"),
            Constant.messages.getString("crimsonblazordecoder.options.regex.col.regex"),
            Constant.messages.getString("crimsonblazordecoder.options.regex.col.c2s"),
            Constant.messages.getString("crimsonblazordecoder.options.regex.col.s2c")
        };

        private List<RegexEntry> entries = new ArrayList<>();

        @Override
        public int getRowCount() {
            return entries.size();
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
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return true;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RegexEntry entry = entries.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.getName();
                case 1: return entry.getPattern();
                case 2: return entry.isActiveC2S();
                case 3: return entry.isActiveS2C();
                default: return null;
            }
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            RegexEntry entry = entries.get(rowIndex);
            switch (columnIndex) {
                case 0: entry.setName((String) value); break;
                case 1:
                    String newPattern = (String) value;
                    if (newPattern != null && !newPattern.isEmpty()) {
                        try {
                            Pattern.compile(newPattern);
                        } catch (PatternSyntaxException ex) {
                            fireTableCellUpdated(rowIndex, columnIndex);
                            JOptionPane.showMessageDialog(
                                    OptionsRegexPanel.this,
                                    Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.invalid")
                                            + " " + ex.getMessage(),
                                    Constant.messages.getString("crimsonblazordecoder.options.regex.dialog.error"),
                                    JOptionPane.WARNING_MESSAGE);
                            return;
                        }
                    }
                    entry.setPattern(newPattern);
                    break;
                case 2: entry.setActiveC2S((Boolean) value); break;
                case 3: entry.setActiveS2C((Boolean) value); break;
            }
            fireTableCellUpdated(rowIndex, columnIndex);
            updateConfigFromTable();
        }

        public void addEntry(RegexEntry entry) {
            if (entries.size() >= MAX_REGEX_RULES) return;
            entries.add(entry);
            fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
        }

        public void removeEntry(int row) {
            entries.remove(row);
            fireTableRowsDeleted(row, row);
        }

        public List<RegexEntry> getEntries() {
            return entries;
        }

        public void setEntries(List<RegexEntry> entries) {
            this.entries = new ArrayList<>(entries);
            fireTableDataChanged();
        }
    }

    /** Cell editor for text columns in the regex table. */
    @SuppressWarnings("serial")
    private static class RegexCellEditor extends AbstractCellEditor implements TableCellEditor {
        private final JTextField field = new JTextField();

        @Override
        public Component getTableCellEditorComponent(
                JTable table, Object value, boolean isSelected, int row, int column) {
            field.setText(value != null ? value.toString() : "");
            return field;
        }

        @Override
        public Object getCellEditorValue() {
            return field.getText();
        }
    }

    /** Checkbox renderer for the boolean columns. */
    @SuppressWarnings("serial")
    private static class CheckboxRenderer extends JCheckBox implements TableCellRenderer {
        CheckboxRenderer() {
            setHorizontalAlignment(SwingConstants.CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {
            setSelected(value != null && (Boolean) value);
            if (isSelected) {
                setBackground(table.getSelectionBackground());
            } else {
                setBackground(table.getBackground());
            }
            return this;
        }
    }

    /** Checkbox editor for the boolean columns. */
    @SuppressWarnings("serial")
    private static class CheckboxEditor extends AbstractCellEditor implements TableCellEditor {
        private final JCheckBox checkbox = new JCheckBox();

        CheckboxEditor() {
            checkbox.setHorizontalAlignment(SwingConstants.CENTER);
        }

        @Override
        public Component getTableCellEditorComponent(
                JTable table, Object value, boolean isSelected, int row, int column) {
            checkbox.setSelected(value != null && (Boolean) value);
            return checkbox;
        }

        @Override
        public Object getCellEditorValue() {
            return checkbox.isSelected();
        }
    }
}
