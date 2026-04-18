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
package com.crimsonwall.crimsonblazordecoder.regex;

import java.util.regex.Pattern;

/** A user-defined regex rule that can be matched against decoded Blazor messages. */
public class RegexEntry {

    private String name;
    private String pattern;
    private boolean activeC2S;
    private boolean activeS2C;
    private volatile transient Pattern compiledPattern;

    public RegexEntry() {
        this("", "", false, false);
    }

    public RegexEntry(String name, String pattern, boolean activeC2S, boolean activeS2C) {
        this.name = name;
        this.pattern = pattern;
        this.activeC2S = activeC2S;
        this.activeS2C = activeS2C;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
        this.compiledPattern = null;
    }

    public boolean isActiveC2S() {
        return activeC2S;
    }

    public void setActiveC2S(boolean activeC2S) {
        this.activeC2S = activeC2S;
    }

    public boolean isActiveS2C() {
        return activeS2C;
    }

    public void setActiveS2C(boolean activeS2C) {
        this.activeS2C = activeS2C;
    }

    /** Returns a compiled Pattern, or null if the pattern string is invalid or empty. */
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
