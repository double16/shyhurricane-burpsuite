package com.github.double16;

import burp.api.montoya.http.message.HttpHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionShyHurricaneForwarderTest {

    private ExtensionShyHurricaneForwarder ext;

    @BeforeEach
    void setUp() {
        ext = new ExtensionShyHurricaneForwarder();
    }

    @Nested
    @DisplayName("shouldSkip(contentType) logic")
    class ShouldSkipTests {
        private Method shouldSkip;

        @BeforeEach
        void reflect() throws Exception {
            shouldSkip = ExtensionShyHurricaneForwarder.class.getDeclaredMethod("shouldSkip", String.class);
            shouldSkip.setAccessible(true);
        }

        private boolean callShouldSkip(String ct) throws Exception {
            return (boolean) shouldSkip.invoke(ext, ct);
        }

        @Test
        void nullAndEmpty_returnFalse() throws Exception {
            assertFalse(callShouldSkip(null));
            assertFalse(callShouldSkip(""));
        }

        @Test
        void prefixes_audio_video_font_binary_returnTrue() throws Exception {
            assertTrue(callShouldSkip("audio/mpeg"));
            assertTrue(callShouldSkip("video/mp4"));
            assertTrue(callShouldSkip("font/woff2"));
            assertTrue(callShouldSkip("binary/octet-stream"));
        }

        @Test
        void images_nonSvg_returnTrue_svgAllowed() throws Exception {
            assertTrue(callShouldSkip("image/png"));
            assertTrue(callShouldSkip("image/jpeg"));
            assertFalse(callShouldSkip("image/svg+xml"));
        }

        @Test
        void explicitSkipTypes_returnTrue() throws Exception {
            assertTrue(callShouldSkip("application/octet-stream"));
            assertTrue(callShouldSkip("application/pdf"));
            assertTrue(callShouldSkip("application/x-zip-compressed"));
            assertTrue(callShouldSkip("application/font-woff2"));
        }

        @Test
        void jsonXmlSubtypes_passThrough_returnFalse() throws Exception {
            assertFalse(callShouldSkip("application/vnd.api+json"));
            assertFalse(callShouldSkip("application/problem+json"));
            assertFalse(callShouldSkip("application/vnd.company+xml"));
        }

        @Test
        void caseInsensitive_handling() throws Exception {
            assertTrue(callShouldSkip("IMAGE/PNG"));
            assertTrue(callShouldSkip("Application/PDF"));
            assertFalse(callShouldSkip("Application/Problem+Json"));
        }
    }

    @Nested
    @DisplayName("toKatanaHeaders(headers) behavior")
    class ToKatanaHeadersTests {
        private Method toKatanaHeaders;

        @BeforeEach
        void reflect() throws Exception {
            toKatanaHeaders = ExtensionShyHurricaneForwarder.class.getDeclaredMethod("toKatanaHeaders", List.class);
            toKatanaHeaders.setAccessible(true);
        }

        @SuppressWarnings("unchecked")
        private Map<String, String> callToKatanaHeaders(List<HttpHeader> headers) throws Exception {
            return (Map<String, String>) toKatanaHeaders.invoke(ext, headers);
        }

        private static HttpHeader hdr(String name, String value) {
            return new HttpHeader() {
                @Override
                public String name() { return name; }

                @Override
                public String value() { return value; }
            };
        }

        @Test
        void lowercasesNamesAndKeepsValues() throws Exception {
            List<HttpHeader> headers = List.of(
                    hdr("Content-Type", "text/html"),
                    hdr("X-Custom", "abc")
            );

            Map<String, String> map = callToKatanaHeaders(headers);
            assertEquals("text/html", map.get("content-type"));
            assertEquals("abc", map.get("x-custom"));
            assertFalse(map.containsKey("Content-Type"));
        }

        @Test
        void duplicatesConcatenateWithSemicolons_inOrder() throws Exception {
            List<HttpHeader> headers = new ArrayList<>();
            headers.add(hdr("Set-Cookie", "k1=v1"));
            headers.add(hdr("set-cookie", "k2=v2"));
            headers.add(hdr("SET-COOKIE", "k3=v3"));

            Map<String, String> map = callToKatanaHeaders(headers);
            assertEquals("k1=v1;k2=v2;k3=v3", map.get("set-cookie"));
        }
    }
}
