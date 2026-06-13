package com.github.double16;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;

class ShyHurricaneConfigTab extends JPanel {

    private final ExtensionShyHurricaneForwarder ext;

    private final JCheckBox onlyInScopeCheck;
    private final JTextField urlField;
    private final JComboBox<AuditIssueConfidence> confidenceBox;
    private final JComboBox<AuditIssueSeverity> severityBox;
    private final JCheckBox allToolsCheck;
    private final java.util.Map<ToolType, JCheckBox> toolChecks = new java.util.EnumMap<>(ToolType.class);

    ShyHurricaneConfigTab(ExtensionShyHurricaneForwarder ext, MontoyaApi api) {
        super(new GridBagLayout());
        this.ext = ext;

        onlyInScopeCheck = new JCheckBox("Capture only in-scope traffic", ext.isOnlyInScope());
        urlField = new JTextField(ext.getMcpServerUrl(), 30);

        confidenceBox = new JComboBox<>(
                Arrays.stream(AuditIssueConfidence.values()).toArray(AuditIssueConfidence[]::new));
        confidenceBox.setSelectedItem(ext.getMinimumConfidenceLevel());

        severityBox = new JComboBox<>(
                Arrays.stream(AuditIssueSeverity.values()).toArray(AuditIssueSeverity[]::new));
        severityBox.setSelectedItem(ext.getMinimumSeverityLevel());

        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> applyConfig());

        // layout
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        c.gridx = 0;
        c.gridy = 0;
        add(new JLabel("MCP server URL:"), c);
        c.gridx = 1;
        add(urlField, c);

        c.gridx = 0;
        c.gridy = 1;
        add(new JLabel("Minimum confidence:"), c);
        c.gridx = 1;
        add(confidenceBox, c);

        c.gridx = 0;
        c.gridy = 2;
        add(new JLabel("Minimum severity:"), c);
        c.gridx = 1;
        add(severityBox, c);

        c.gridx = 0;
        c.gridy = 3;
        c.gridwidth = 2;
        add(onlyInScopeCheck, c);

        // Tools section
        c.gridy = 4;
        c.gridwidth = 1;
        add(new JLabel("Tools to capture:"), c);

        // Build tools panel with All + individual tool checkboxes
        JPanel toolsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints tc = new GridBagConstraints();
        tc.insets = new Insets(2, 2, 2, 2);
        tc.anchor = GridBagConstraints.WEST;
        tc.gridx = 0;
        tc.gridy = 0;

        allToolsCheck = new JCheckBox("All", ext.isAllTools());
        toolsPanel.add(allToolsCheck, tc);

        // Next row for individual tools
        tc.gridy++;
        tc.gridx = 0;
        for (ToolType t : ToolType.values()) {
            JCheckBox cb = new JCheckBox(
                    prettyToolLabel(t.name()),
                    ext.getSelectedToolNames().contains(t.name())
            );
            toolChecks.put(t, cb);
            toolsPanel.add(cb, tc);
            tc.gridx++;
            if (tc.gridx % 3 == 0) { // wrap every 3 for compactness
                tc.gridx = 0;
                tc.gridy++;
            }
        }

        c.gridx = 1;
        add(toolsPanel, c);

        c.gridx = 0;
        c.gridwidth = 2;
        c.gridy = 5;
        c.anchor = GridBagConstraints.EAST;
        add(saveBtn, c);
    }

    private static String prettyToolLabel(String raw) {
        // e.g., RECORDED_LOGIN_REPLAYER -> Recorded Login Replayer
        String[] parts = raw.split("_");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i].toLowerCase();
            if (p.isEmpty()) continue;
            sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1));
            if (i < parts.length - 1) sb.append(' ');
        }
        return sb.toString();
    }

    private void applyConfig() {
        ext.setOnlyInScope(onlyInScopeCheck.isSelected());
        ext.setMcpServerUrl(urlField.getText().trim());
        ext.setMinimumConfidenceLevel((AuditIssueConfidence) confidenceBox.getSelectedItem());
        ext.setMinimumSeverityLevel((AuditIssueSeverity) severityBox.getSelectedItem());
        ext.setAllTools(allToolsCheck.isSelected());

        java.util.Set<String> selected = new java.util.HashSet<>();
        for (java.util.Map.Entry<ToolType, JCheckBox> e : toolChecks.entrySet()) {
            if (e.getValue().isSelected()) {
                selected.add(e.getKey().name());
            }
        }
        ext.setSelectedToolNames(selected);
        JOptionPane.showMessageDialog(this, "Configuration saved.", "ShyHurricane", JOptionPane.INFORMATION_MESSAGE);
    }
}
