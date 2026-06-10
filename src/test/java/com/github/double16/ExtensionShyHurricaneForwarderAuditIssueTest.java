package com.github.double16;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionShyHurricaneForwarderAuditIssueTest {

    private static class RecordingServer implements HttpHandler, AutoCloseable {
        HttpServer server;
        volatile String lastPath;
        volatile String lastBody;
        volatile int requestCount;

        RecordingServer() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this);
            server.setExecutor(null);
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            lastPath = exchange.getRequestURI().getPath();
            lastBody = readAll(exchange.getRequestBody());
            requestCount++;
            byte[] ok = "OK".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, ok.length);
            exchange.getResponseBody().write(ok);
            exchange.close();
        }

        private static String readAll(InputStream in) throws IOException {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }

        @Override
        public void close() {
            if (server != null) server.stop(0);
        }
    }

    private ExtensionShyHurricaneForwarder ext;
    private RecordingServer server;

    @BeforeEach
    void setUp() throws Exception {
        ext = new ExtensionShyHurricaneForwarder();
        server = new RecordingServer();
        ext.setMcpServerUrl(server.baseUrl());
        // Make scope irrelevant for these tests to avoid needing request/response objects
        ext.setOnlyInScope(false);
        // Keep permissive defaults
        ext.setMinimumConfidenceLevel(AuditIssueConfidence.FIRM);
        ext.setMinimumSeverityLevel(AuditIssueSeverity.INFORMATION);
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private static AuditIssueDefinition def(String background, String remediation) {
        return new AuditIssueDefinition() {
            @Override public String name() { return "Definition"; }
            @Override public String background() { return background; }
            @Override public String remediation() { return remediation; }

            @Override
            public AuditIssueSeverity typicalSeverity() {
                return null;
            }

            @Override
            public int typeIndex() {
                return 0;
            }
        };
    }

    private static AuditIssue makeIssue(String name,
                                        String baseUrl,
                                        AuditIssueSeverity severity,
                                        AuditIssueConfidence confidence,
                                        String detail,
                                        String remediation,
                                        AuditIssueDefinition definition,
                                        List<?> requestResponses) {
        return new AuditIssue() {
            @Override public String name() { return name; }
            @Override public String baseUrl() { return baseUrl; }
            @Override public AuditIssueSeverity severity() { return severity; }
            @Override public AuditIssueConfidence confidence() { return confidence; }
            @Override public String detail() { return detail; }
            @Override public String remediation() { return remediation; }

            @Override
            public HttpService httpService() {
                return null;
            }

            @Override public List requestResponses() { return requestResponses; }

            @Override
            public List<Interaction> collaboratorInteractions() {
                return List.of();
            }

            @Override public AuditIssueDefinition definition() { return definition; }
        };
    }

    @Test
    @DisplayName("handleNewAuditIssue posts to /findings when filters pass")
    void postsFinding_whenPassesFilters() throws Exception {
        AuditIssue issue = makeIssue(
                "Test Issue",
                "https://example.com",
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.FIRM,
                "Some details",
                "Some remediation",
                def("Background text", "Definition remediation"),
                Collections.emptyList()
        );

        ext.handleNewAuditIssue(issue);

        assertEquals(1, server.requestCount, "Expected one POST to findings");
        assertEquals("/findings", server.lastPath);

        // Validate JSON payload basics
        ObjectMapper mapper = new ObjectMapper();
        @SuppressWarnings("unchecked")
        Map<String, Object> json = mapper.readValue(server.lastBody, Map.class);
        assertEquals("https://example.com", json.get("target"));
        assertEquals("Test Issue at https://example.com", json.get("title"));
        assertTrue(((String) json.get("markdown")).contains("# Test Issue at https://example.com"));
    }

    @Test
    @DisplayName("handleNewAuditIssue does not post when filtered by confidence or severity")
    void doesNotPost_whenFilteredByConfidenceOrSeverity() {
        // Filter out when confidence is LOWER than the configured minimum
        ext.setMinimumConfidenceLevel(AuditIssueConfidence.FIRM);
        AuditIssue lowConfidence = makeIssue(
                "Issue Low Confidence",
                "https://target",
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.TENTATIVE,
                null,
                null,
                def("bg", "rem"),
                Collections.emptyList());
        ext.handleNewAuditIssue(lowConfidence);
        assertEquals(0, server.requestCount);

        // Filter out when severity is LOWER than the configured minimum
        ext.setMinimumSeverityLevel(AuditIssueSeverity.HIGH);
        AuditIssue lowSeverity = makeIssue(
                "Issue Low Severity",
                "https://target",
                AuditIssueSeverity.INFORMATION,
                AuditIssueConfidence.FIRM,
                null,
                null,
                def("bg", "rem"),
                Collections.emptyList());
        ext.handleNewAuditIssue(lowSeverity);
        assertEquals(0, server.requestCount);
    }
}
