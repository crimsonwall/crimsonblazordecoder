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

import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manages regex configuration for the Crimson Blazor Decoder add-on.
 *
 * <p>This class provides a centralized configuration management for regex rules
 * used to match and highlight patterns in decoded Blazor messages. It delegates
 * persistence to {@link RegexStorage}.
 */
public class RegexConfig {

    private static final Logger LOGGER = LogManager.getLogger(RegexConfig.class);

    private final RegexStorage storage = new RegexStorage();
    private volatile List<RegexEntry> entries;

    /** Cached list of active C2S entries, invalidated on mutation. */
    private volatile List<RegexEntry> cachedActiveC2SEntries;

    /** Cached list of active S2C entries, invalidated on mutation. */
    private volatile List<RegexEntry> cachedActiveS2CEntries;

    public RegexConfig() {
        this.entries = new ArrayList<>();
    }

    /** Load config from disk. Falls back to defaults if no file exists. */
    public void load() {
        entries = storage.load();
        if (entries.isEmpty()) {
            entries = RegexStorage.createDefaults();
            storage.save(entries);
        }
        cachedActiveC2SEntries = null;
        cachedActiveS2CEntries = null;
    }

    /** Save the current regex entries via RegexStorage. */
    public void save() {
        storage.save(entries);
    }

    // --- Getters and setters ---

    public List<RegexEntry> getEntries() {
        return new ArrayList<>(entries);
    }

    public void setEntries(List<RegexEntry> entries) {
        this.entries = new ArrayList<>(entries);
        cachedActiveC2SEntries = null;
        cachedActiveS2CEntries = null;
    }

    /** Get all enabled C2S entries with valid compiled patterns. Result is cached until entries change. */
    public List<RegexEntry> getActiveC2SEntries() {
        List<RegexEntry> cached = cachedActiveC2SEntries;
        if (cached != null) {
            return cached;
        }
        List<RegexEntry> active = new ArrayList<>();
        for (RegexEntry entry : entries) {
            if (entry.isActiveC2S() && entry.getCompiledPattern() != null) {
                active.add(entry);
            }
        }
        cachedActiveC2SEntries = active;
        return active;
    }

    /** Get all enabled S2C entries with valid compiled patterns. Result is cached until entries change. */
    public List<RegexEntry> getActiveS2CEntries() {
        List<RegexEntry> cached = cachedActiveS2CEntries;
        if (cached != null) {
            return cached;
        }
        List<RegexEntry> active = new ArrayList<>();
        for (RegexEntry entry : entries) {
            if (entry.isActiveS2C() && entry.getCompiledPattern() != null) {
                active.add(entry);
            }
        }
        cachedActiveS2CEntries = active;
        return active;
    }
}
