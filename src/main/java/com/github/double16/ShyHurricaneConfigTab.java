// ShyHurricaneConfigTab.java
package com.github.double16;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;

class ShyHurricaneConfigTab extends JPanel {

    private final ExtensionShyHurricaneForwarder ext;

    // UI controls ------------------------------------------------------------
    private final JCheckBox onlyInScopeCheck;
    private final JTextField urlField;
    private final JComboBox<AuditIssueConfidence> confidenceBox;
    private final JComboBox<AuditIssueSeverity> severityBox;

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

        // layout -------------------------------------------------------------
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

        c.gridy = 4;
        c.anchor = GridBagConstraints.EAST;
        add(saveBtn, c);
    }

    private void applyConfig() {
        ext.setOnlyInScope(onlyInScopeCheck.isSelected());
        ext.setMcpServerUrl(urlField.getText().trim());
        ext.setMinimumConfidenceLevel((AuditIssueConfidence) confidenceBox.getSelectedItem());
        ext.setMinimumSeverityLevel((AuditIssueSeverity) severityBox.getSelectedItem());
        JOptionPane.showMessageDialog(this, "Configuration saved.", "ShyHurricane", JOptionPane.INFORMATION_MESSAGE);
    }
}
