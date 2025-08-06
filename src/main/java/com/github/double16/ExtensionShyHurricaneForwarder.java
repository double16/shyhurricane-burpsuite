package com.github.double16;

import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;

import java.net.URL;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;

@SuppressWarnings("unused")
public class ExtensionShyHurricaneForwarder implements BurpExtension, ExtensionUnloadingHandler, HttpHandler, AuditIssueHandler {

    private static final String NAME = "ShyHurricane";
    private static final String INDEX_PATH = "/index";
    private static final String FINDINGS_PATH = "/findings";


    /**
     * Prefixes that should always be skipped.
     */
    private static final String[] SKIP_PREFIXES = {
            "audio/",
            "video/",
            "font/",
            "binary/"
    };

    /**
     * Exact content-types that should be skipped.
     */
    private static final Set<String> SKIP_TYPES = Set.of(
            "application/octet-stream",
            "application/pdf",
            "application/x-pdf",
            "application/zip",
            "application/x-zip-compressed",
            "application/x-protobuf",
            "application/font-woff",
            "application/font-woff2",
            "application/vnd.ms-fontobject"
    );

    /* Preference keys */
    private static final String PREF_ONLY_IN_SCOPE = "onlyInScope";
    private static final String PREF_MCP_SERVER_URL = "mcpServerUrl";
    private static final String PREF_MIN_CONF = "minConfidence";
    private static final String PREF_MIN_SEV = "minSeverity";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final List<Registration> registrations = new ArrayList<>();

    private volatile boolean onlyInScope = true;
    private volatile String mcpServerUrl = "http://localhost:8000";
    private volatile AuditIssueConfidence minimumConfidenceLevel = AuditIssueConfidence.FIRM;
    private volatile AuditIssueSeverity minimumSeverityLevel = AuditIssueSeverity.INFORMATION;

    private Preferences prefs;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        api.extension().registerUnloadingHandler(this);

        this.prefs = api.persistence().preferences();
        loadPrefs();

        registrations.add(api.http().registerHttpHandler(this));
        registrations.add(api.scanner().registerAuditIssueHandler(this));
        api.userInterface().registerSuiteTab(NAME, new ShyHurricaneConfigTab(this, api));
    }

    @Override
    public void extensionUnloaded() {
        for(Registration registration : registrations) {
            registration.deregister();
        }
        registrations.clear();
    }

    private void loadPrefs() {
        onlyInScope = Optional.ofNullable(prefs.getBoolean(PREF_ONLY_IN_SCOPE)).orElse(onlyInScope);
        mcpServerUrl = Optional.ofNullable(prefs.getString(PREF_MCP_SERVER_URL)).orElse(mcpServerUrl);
        minimumConfidenceLevel = AuditIssueConfidence.valueOf(Optional.ofNullable(
                prefs.getString(PREF_MIN_CONF)).orElse(minimumConfidenceLevel.name()));
        minimumSeverityLevel = AuditIssueSeverity.valueOf(Optional.ofNullable(
                prefs.getString(PREF_MIN_SEV)).orElse(minimumSeverityLevel.name()));
    }

    private void savePrefs() {
        prefs.setBoolean(PREF_ONLY_IN_SCOPE, onlyInScope);
        prefs.setString(PREF_MCP_SERVER_URL, mcpServerUrl);
        prefs.setString(PREF_MIN_CONF, minimumConfidenceLevel.name());
        prefs.setString(PREF_MIN_SEV, minimumSeverityLevel.name());
    }

    boolean isOnlyInScope() {
        return onlyInScope;
    }

    String getMcpServerUrl() {
        return mcpServerUrl;
    }

    AuditIssueConfidence getMinimumConfidenceLevel() {
        return minimumConfidenceLevel;
    }

    AuditIssueSeverity getMinimumSeverityLevel() {
        return minimumSeverityLevel;
    }

    void setOnlyInScope(boolean v) {
        onlyInScope = v;
        savePrefs();
    }

    void setMcpServerUrl(String v) {
        mcpServerUrl = v;
        savePrefs();
    }

    void setMinimumConfidenceLevel(AuditIssueConfidence v) {
        minimumConfidenceLevel = v;
        savePrefs();
    }

    void setMinimumSeverityLevel(AuditIssueSeverity v) {
        minimumSeverityLevel = v;
        savePrefs();
    }

    @Override
    public void handleNewAuditIssue(AuditIssue auditIssue) {
        if (auditIssue.confidence().compareTo(minimumConfidenceLevel) > 0) {
            return;
        }
        if (auditIssue.severity().compareTo(minimumSeverityLevel) > 0) {
            return;
        }

        if (onlyInScope) {
            boolean anyInScope = false;
            for (HttpRequestResponse rr : auditIssue.requestResponses()) {
                if (rr.request().isInScope()) {
                    anyInScope = true;
                    break;
                }
            }
            if (!anyInScope) {
                return;
            }
        }

        try {
            String title = auditIssue.name() + " at " + auditIssue.baseUrl();
            StringBuilder markdown = new StringBuilder();
            markdown.append("# ").append(title).append("\n\n");
            markdown.append(String.format("""
                    **Summary**
                    Severity: %s
                    Confidence: %s
                    URL: `%s`

                    %s
                    """, auditIssue.severity().name(), auditIssue.confidence().name(), auditIssue.baseUrl(), auditIssue.definition().background()));
            if (StringUtils.isNotBlank(auditIssue.detail())) {
                markdown.append(auditIssue.detail()).append("\n");
            }
            markdown.append("\n**Reproduction Steps**\n");
            for(HttpRequestResponse rr : auditIssue.requestResponses()) {
                markdown.append(rr.request().method());
                markdown.append(" ");
                markdown.append(rr.request().url());
                String requestBody = StringUtils.truncate(rr.request().bodyToString(), 1024);
                if (StringUtils.isNotBlank(requestBody)) {
                    markdown.append("\n");
                    markdown.append(requestBody);
                }
                markdown.append("\n\n");
                markdown.append(rr.response().statusCode());
                markdown.append(" ");
                markdown.append(rr.response().reasonPhrase());
                String responseBody = StringUtils.truncate(rr.response().bodyToString(), 1024);
                if (StringUtils.isNotBlank(responseBody)) {
                    markdown.append("\n");
                    markdown.append(responseBody);
                }
                markdown.append("\n\n\n");
            }
            markdown.append("\n**Solution**\n");
            if (StringUtils.isNotBlank(auditIssue.remediation())) {
                markdown.append("\n").append(auditIssue.remediation()).append("\n");
            }
            if (StringUtils.isNotBlank(auditIssue.definition().remediation())) {
                markdown.append("\n").append(auditIssue.definition().remediation()).append("\n");
            }
            postFinding(auditIssue.baseUrl(), title, markdown.toString());

        } catch (Exception e) {
            System.err.println("[ShyHurricaneForwarder] Error posting finding: " + e.getMessage());
        }

    }

    private void postFinding(String target, String title, String markdown) throws Exception {
        Map<String, Object> data = new HashMap<>();
        data.put("target", target);
        data.put("title", title);
        data.put("markdown", markdown);
        postData(mcpServerUrl + FINDINGS_PATH, data);
    }

    private boolean shouldSkip(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return false;
        }

        String ct = contentType.toLowerCase();

        // Pass through JSON/XML subtypes (e.g., "application/vnd.api+json")
        if (ct.contains("+json") || ct.contains("+xml")) {
            return false;
        }

        // Skip if it matches one of the configured prefixes
        for (String prefix : SKIP_PREFIXES) {
            if (ct.startsWith(prefix)) {
                return true;
            }
        }

        // Skip non-SVG images
        if (ct.startsWith("image/") && !ct.contains("svg")) {
            return true;
        }

        // Skip any explicitly listed types
        return SKIP_TYPES.contains(ct);
    }

    /**
     * Katana headers are lowercase with underscores.
     */
    private Map<String, String> toKatanaHeaders(List<HttpHeader> headers) {
        Map<String, String> map = new HashMap<>();
        for (HttpHeader header : headers) {
            String katanaHeaderName = header.name().toLowerCase();
            if (map.containsKey(katanaHeaderName)) {
                map.put(katanaHeaderName, map.get(katanaHeaderName) + ";" + header.value());
            } else {
                map.put(katanaHeaderName, header.value());
            }
        }
        return map;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        if (onlyInScope && !httpResponseReceived.initiatingRequest().isInScope()) {
            return ResponseReceivedAction.continueWith(httpResponseReceived);
        }

        HttpRequest req = httpResponseReceived.initiatingRequest();
        List<HttpHeader> req_hdr = req.headers();
        List<HttpHeader> res_hdr = httpResponseReceived.headers();

        String contentType = httpResponseReceived.headerValue("Content-Type");
        if (shouldSkip(contentType)) {
            return ResponseReceivedAction.continueWith(httpResponseReceived);
        }

        String now = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        Map<String, Object> request = new HashMap<>();
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> entry = new HashMap<>();
        entry.put("timestamp", now);
        entry.put("request", request);
        entry.put("response", response);

        request.put("method", req.method());
        request.put("endpoint", req.url());
        request.put("headers", toKatanaHeaders(req_hdr));
        try {
            request.put("body", req.bodyToString());
        } catch (Exception e) {
            // bad unicode chars or binary data
        }

        response.put("status_code", httpResponseReceived.statusCode());
        response.put("headers", toKatanaHeaders(res_hdr));
        try {
            response.put("body", httpResponseReceived.bodyToString());
        } catch (Exception e) {
            // bad unicode chars or binary data
        }
//        response.put("rtt", msg.getTimeElapsedMillis() / 1000.0);

        try {
            postIndex(entry);
        } catch (Exception e) {
            System.err.println("[ShyHurricaneForwarder] Error posting index: " + e.getMessage());
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    private void postIndex(Map<String, Object> data) throws Exception {
        postData(mcpServerUrl + INDEX_PATH, data);
    }

    private void postData(String urlStr, Map<String, Object> data) throws Exception {
        String jsonBody = MAPPER.writeValueAsString(data);

        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (var writer = new OutputStreamWriter(conn.getOutputStream())) {
            writer.write(jsonBody);
        }

        int status = conn.getResponseCode();
        if (status >= 400) {
            System.err.println("[ShyHurricaneForwarder] Failed to POST " + urlStr + ": HTTP " + status);
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }
}
