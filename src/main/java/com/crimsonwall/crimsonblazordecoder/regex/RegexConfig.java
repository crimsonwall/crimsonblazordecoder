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

import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manages regex configuration for the Crimson Blazor Decoder add-on.
 *
 * <p>This class provides centralized configuration management for regex rules
 * used to match and highlight patterns in decoded Blazor messages. It delegates
 * persistence to {@link RegexStorage}.
 *
 * <p>All access to the internal entries list is synchronized to ensure thread safety
 * between the WebSocket observer thread and the Swing EDT.
 */
public class RegexConfig {

    private static final Logger LOGGER = LogManager.getLogger(RegexConfig.class);

    private final RegexStorage storage = new RegexStorage();

    /** Guarded by {@code this}. */
    private List<RegexEntry> entries = new ArrayList<>();

    /** Cached list of active C2S entries, invalidated on mutation. */
    private volatile List<RegexEntry> cachedActiveC2SEntries;

    /** Cached list of active S2C entries, invalidated on mutation. */
    private volatile List<RegexEntry> cachedActiveS2CEntries;

    /** Creates an empty regex configuration. */
    public RegexConfig() {}

    /**
     * Loads config from disk. Falls back to defaults if no file exists.
     */
    public synchronized void load() {
        entries = storage.load();
        if (entries.isEmpty()) {
            entries = RegexStorage.createDefaults();
            storage.save(entries);
        }
        cachedActiveC2SEntries = null;
        cachedActiveS2CEntries = null;
    }

    /**
     * Saves the current regex entries via {@link RegexStorage}.
     */
    public synchronized void save() {
        storage.save(entries);
    }

    /**
     * Returns a defensive copy of all regex entries.
     *
     * @return a new list containing all current entries
     */
    public synchronized List<RegexEntry> getEntries() {
        return new ArrayList<>(entries);
    }

    /**
     * Replaces all entries with a defensive copy of the given list.
     *
     * @param entries the new entries to set
     */
    public synchronized void setEntries(List<RegexEntry> entries) {
        this.entries = new ArrayList<>(entries);
        cachedActiveC2SEntries = null;
        cachedActiveS2CEntries = null;
    }

    /**
     * Returns all enabled client-to-server entries with valid compiled patterns.
     *
     * <p>The result is cached until entries change.
     *
     * @return cached list of active C2S regex entries
     */
    public List<RegexEntry> getActiveC2SEntries() {
        List<RegexEntry> cached = cachedActiveC2SEntries;
        if (cached != null) {
            return cached;
        }
        List<RegexEntry> snapshot;
        synchronized (this) {
            snapshot = new ArrayList<>(entries);
        }
        List<RegexEntry> active = new ArrayList<>();
        for (RegexEntry entry : snapshot) {
            if (entry.isActiveC2S() && entry.getCompiledPattern() != null) {
                active.add(entry);
            }
        }
        cachedActiveC2SEntries = active;
        return active;
    }

    /**
     * Returns all enabled server-to-client entries with valid compiled patterns.
     *
     * <p>The result is cached until entries change.
     *
     * @return cached list of active S2C regex entries
     */
    public List<RegexEntry> getActiveS2CEntries() {
        List<RegexEntry> cached = cachedActiveS2CEntries;
        if (cached != null) {
            return cached;
        }
        List<RegexEntry> snapshot;
        synchronized (this) {
            snapshot = new ArrayList<>(entries);
        }
        List<RegexEntry> active = new ArrayList<>();
        for (RegexEntry entry : snapshot) {
            if (entry.isActiveS2C() && entry.getCompiledPattern() != null) {
                active.add(entry);
            }
        }
        cachedActiveS2CEntries = active;
        return active;
    }
}
