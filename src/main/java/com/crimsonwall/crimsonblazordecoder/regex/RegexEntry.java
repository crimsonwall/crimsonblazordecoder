/*
 * Crimson Blazor Decoder - Blazor Pack Decoder for ZAP.
 *
 * Renico Koen / Crimson Wall / 2026.
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
package com.crimsonwall.crimsonblazordecoder.regex;

import java.util.regex.Pattern;

/**
 * A user-defined regex rule that can be matched against decoded Blazor messages.
 *
 * <p>Each entry has a name, a regex pattern string, and separate enable flags for
 * client-to-server (C2S) and server-to-client (S2C) traffic directions.
 */
public class RegexEntry {

    private String name;
    private String pattern;
    private boolean activeC2S;
    private boolean activeS2C;

    /** Cached compiled pattern, lazily initialised. Volatile for thread-safe publish. */
    private volatile transient Pattern compiledPattern;

    /**
     * Creates an empty, inactive entry.
     */
    public RegexEntry() {
        this("", "", false, false);
    }

    /**
     * Creates a regex entry with the given properties.
     *
     * @param name     display name of the rule
     * @param pattern  Java regex pattern string
     * @param activeC2S whether this rule is active for client-to-server traffic
     * @param activeS2C whether this rule is active for server-to-client traffic
     */
    public RegexEntry(String name, String pattern, boolean activeC2S, boolean activeS2C) {
        this.name = name;
        this.pattern = pattern;
        this.activeC2S = activeC2S;
        this.activeS2C = activeS2C;
    }

    /**
     * Returns the display name of this rule.
     *
     * @return the rule name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the display name of this rule.
     *
     * @param name the new name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Returns the regex pattern string.
     *
     * @return the pattern string, never null
     */
    public String getPattern() {
        return pattern;
    }

    /**
     * Sets the regex pattern string and invalidates the cached compiled pattern.
     *
     * @param pattern the new pattern string
     */
    public void setPattern(String pattern) {
        this.pattern = pattern;
        this.compiledPattern = null;
    }

    /**
     * Returns whether this rule is active for client-to-server traffic.
     *
     * @return {@code true} if active for C2S direction
     */
    public boolean isActiveC2S() {
        return activeC2S;
    }

    /**
     * Sets whether this rule is active for client-to-server traffic.
     *
     * @param activeC2S {@code true} to enable for C2S direction
     */
    public void setActiveC2S(boolean activeC2S) {
        this.activeC2S = activeC2S;
    }

    /**
     * Returns whether this rule is active for server-to-client traffic.
     *
     * @return {@code true} if active for S2C direction
     */
    public boolean isActiveS2C() {
        return activeS2C;
    }

    /**
     * Sets whether this rule is active for server-to-client traffic.
     *
     * @param activeS2C {@code true} to enable for S2C direction
     */
    public void setActiveS2C(boolean activeS2C) {
        this.activeS2C = activeS2C;
    }

    /**
     * Returns a compiled {@link Pattern}, or {@code null} if the pattern string is empty or invalid.
     *
     * <p>The compiled pattern is cached for reuse. Thread-safe via volatile publish.
     *
     * @return the compiled pattern, or null if unavailable
     */
    public Pattern getCompiledPattern() {
        if (compiledPattern != null) {
            return compiledPattern;
        }
        if (pattern == null || pattern.isEmpty()) {
            return null;
        }
        try {
            compiledPattern = Pattern.compile(pattern);
            return compiledPattern;
        } catch (Exception e) {
            return null;
        }
    }
}
