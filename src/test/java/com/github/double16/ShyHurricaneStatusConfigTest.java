package com.github.double16;

import static org.junit.jupiter.api.Assertions.*;

import burp.api.montoya.persistence.Preferences;
import java.awt.*;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.swing.*;
import org.junit.jupiter.api.Test;

class ShyHurricaneStatusConfigTest {
  @Test
  void savingAppliesSelectedAndUnselectedToolsAndStatuses() throws Exception {
    SwingUtilities.invokeAndWait(
        () -> {
          final var ext = new ExtensionShyHurricaneForwarder();
          final var panel = new ShyHurricaneConfigTab(ext, null);
          final Map<String, JCheckBox> checks = new HashMap<>();
          collectChecks(panel, checks);
          checks.get("2xx").setSelected(false);
          checks.get("4xx").setSelected(true);
          checks.get("All").setSelected(false);
          checks.get("Proxy").setSelected(true);
          checks.get("Capture only in-scope traffic").setSelected(false);
          clickSave(panel);
          assertEquals(Set.of(4), ext.getSelectedStatusClasses());
          assertEquals(Set.of("PROXY"), ext.getSelectedToolNames());
          assertFalse(ext.isAllTools());
          assertFalse(ext.isOnlyInScope());
        });
  }

  private void clickSave(Container container) {
    for (Component component : container.getComponents()) {
      if (component instanceof JButton button && button.getText().equals("Save")) {
        // All settings are applied before the confirmation dialog; headless tests cannot show it.
        assertThrows(HeadlessException.class, () -> button.doClick(0));
        return;
      }
      if (component instanceof Container child) clickSave(child);
    }
  }

  @Test
  void preferencesPreserveDefaultsSelectionsAndEmptySelection() throws Exception {
    Map<String, Object> values = new HashMap<>();
    Preferences preferences =
        (Preferences)
            Proxy.newProxyInstance(
                Preferences.class.getClassLoader(),
                new Class[] {Preferences.class},
                (proxy, method, args) -> {
                  if (method.getName().startsWith("get")) return values.get(args[0]);
                  if (method.getName().startsWith("set")) values.put((String) args[0], args[1]);
                  return null;
                });
    ExtensionShyHurricaneForwarder ext = load(preferences);
    assertEquals(Set.of(2), ext.getSelectedStatusClasses());
    ext.setSelectedStatusClasses(Set.of(3, 5));
    assertEquals(Set.of(3, 5), load(preferences).getSelectedStatusClasses());
    ext.setSelectedStatusClasses(Set.of());
    assertEquals(Set.of(), load(preferences).getSelectedStatusClasses());
    values.put("selectedStatusClassesCsv", "1,2,6,invalid");
    assertEquals(Set.of(2), load(preferences).getSelectedStatusClasses());
  }

  private ExtensionShyHurricaneForwarder load(Preferences preferences) throws Exception {
    ExtensionShyHurricaneForwarder ext = new ExtensionShyHurricaneForwarder();
    var field = ExtensionShyHurricaneForwarder.class.getDeclaredField("prefs");
    field.setAccessible(true);
    field.set(ext, preferences);
    var method = ExtensionShyHurricaneForwarder.class.getDeclaredMethod("loadPrefs");
    method.setAccessible(true);
    method.invoke(ext);
    return ext;
  }

  @Test
  void statusSelectionIsImmutableAndRejectsUnsupportedClasses() {
    var ext = new ExtensionShyHurricaneForwarder();
    var selection = new java.util.HashSet<>(Set.of(2, 4));
    ext.setSelectedStatusClasses(selection);
    selection.clear();
    assertEquals(Set.of(2, 4), ext.getSelectedStatusClasses());
    assertThrows(UnsupportedOperationException.class, () -> ext.getSelectedStatusClasses().add(3));
    assertThrows(IllegalArgumentException.class, () -> ext.setSelectedStatusClasses(Set.of(1, 2)));
    assertEquals(Set.of(2, 4), ext.getSelectedStatusClasses());
  }

  @Test
  void statusControlsDefaultTo2xxAndSelectAllWithoutApplying() throws Exception {
    SwingUtilities.invokeAndWait(
        () -> {
          var ext = new ExtensionShyHurricaneForwarder();
          var panel = new ShyHurricaneConfigTab(ext, null);
          Map<String, JCheckBox> checks = new HashMap<>();
          collectChecks(panel, checks);
          for (String label : new String[] {"2xx", "3xx", "4xx", "5xx"}) {
            assertEquals(label.equals("2xx"), checks.get(label).isSelected());
          }
          assertFalse(checks.containsKey("1xx"));
          clickSelectAll(panel);
          for (String label : new String[] {"2xx", "3xx", "4xx", "5xx"}) {
            assertTrue(checks.get(label).isSelected());
          }
          assertEquals(Set.of(2), ext.getSelectedStatusClasses());
        });
  }

  private void collectChecks(Container container, Map<String, JCheckBox> checks) {
    for (Component component : container.getComponents()) {
      if (component instanceof JCheckBox check) checks.put(check.getText(), check);
      if (component instanceof Container child) collectChecks(child, checks);
    }
  }

  private void clickSelectAll(Container container) {
    for (Component component : container.getComponents()) {
      if (component instanceof JButton button && button.getText().equals("Select all statuses")) {
        button.doClick();
      }
      if (component instanceof Container child) clickSelectAll(child);
    }
  }
}
