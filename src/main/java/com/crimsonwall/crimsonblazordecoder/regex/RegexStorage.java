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

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.SubnodeConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Loads and saves regex rules using ZAP's XML configuration facilities. */
public class RegexStorage {

    private static final Logger LOGGER = LogManager.getLogger(RegexStorage.class);
    private static final String CONFIG_DIR = "crimsonblazordecoder";
    private static final String CONFIG_FILE = "regex-rules.xml";
    private static final String ROOT_KEY = "regex-rules";
    private static final String RULE_KEY = "rule";

    private final File configFile;

    public RegexStorage() {
        File dir = new File(Constant.getZapHome(), CONFIG_DIR);
        this.configFile = new File(dir, CONFIG_FILE);
    }

    /** Load all saved regex entries from disk. Returns an empty list if none exist. */
    public List<RegexEntry> load() {
        List<RegexEntry> entries = new ArrayList<>();
        if (!configFile.exists()) {
            return entries;
        }

        try {
            ZapXmlConfiguration config = new ZapXmlConfiguration(configFile);
            List<HierarchicalConfiguration> rules = config.configurationsAt(RULE_KEY);
            for (HierarchicalConfiguration rule : rules) {
                String name = rule.getString("[@name]", "");
                String pattern = rule.getString("[@pattern]", "");
                boolean activeC2S = rule.getBoolean("[@activeC2S]", false);
                boolean activeS2C = rule.getBoolean("[@activeS2C]", false);
                entries.add(new RegexEntry(name, pattern, activeC2S, activeS2C));
            }
        } catch (ConfigurationException e) {
            LOGGER.warn("Failed to load regex rules from {}", configFile.getAbsolutePath(), e);
        }
        return entries;
    }

    /** Return a curated set of default security regex rules for first-run. */
    public static List<RegexEntry> createDefaults() {
        List<RegexEntry> defaults = new ArrayList<>();

        // --- PII ---
        defaults.add(new RegexEntry("Email Address",
                "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", true, true));
        defaults.add(new RegexEntry("IPv4 Address",
                "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", true, true));
        defaults.add(new RegexEntry("SA ID Number",
                "\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{7}", true, true));
        defaults.add(new RegexEntry("Credit Card Number",
                "\\b(?:\\d[ -]*?){13,19}\\b", true, true));

        // --- Cloud Provider Keys ---
        defaults.add(new RegexEntry("AWS Access Key",
                "(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}", true, true));
        defaults.add(new RegexEntry("AWS Secret Key",
                "(?i)aws_secret_access_key\\s*[=:]\s*[A-Za-z0-9/+=]{40}", true, true));
        defaults.add(new RegexEntry("GCP API Key",
                "AIza[\\w-]{35}", true, true));
        defaults.add(new RegexEntry("Azure Client Secret",
                "[a-zA-Z0-9_~.-]{3}Q~[a-zA-Z0-9_~.-]{34}", true, true));

        // --- Source Control / CI ---
        defaults.add(new RegexEntry("GitHub PAT",
                "ghp_[0-9a-zA-Z]{36}", true, true));
        defaults.add(new RegexEntry("GitHub OAuth",
                "gho_[0-9a-zA-Z]{36}", true, true));
        defaults.add(new RegexEntry("GitHub Fine-Grained PAT",
                "github_pat_[0-9a-zA-Z_]{82}", true, true));
        defaults.add(new RegexEntry("GitLab PAT",
                "glpat-[0-9a-zA-Z\\-]{20}", true, true));

        // --- Messaging / Webhooks ---
        defaults.add(new RegexEntry("Slack Token",
                "xox[bpers]-[0-9a-zA-Z-]+", true, true));
        defaults.add(new RegexEntry("Slack Webhook",
                "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", true, true));
        defaults.add(new RegexEntry("Discord Bot Token",
                "[MN][a-zA-Z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27}", true, true));
        defaults.add(new RegexEntry("SendGrid API Key",
                "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}", true, true));
        defaults.add(new RegexEntry("Twilio API Key",
                "SK[0-9a-fA-F]{32}", true, true));

        // --- Payments ---
        defaults.add(new RegexEntry("Stripe Secret Key",
                "(?:sk|rk)_test_[a-zA-Z0-9]{10,99}", true, true));
        defaults.add(new RegexEntry("Stripe Live Key",
                "(?:sk|rk)_live_[a-zA-Z0-9]{10,99}", true, true));

        // --- Auth / Crypto ---
        defaults.add(new RegexEntry("JWT Token",
                "ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9/\\\\_-]{17,}\\.[a-zA-Z0-9/\\\\_-]{10,}", true, true));
        defaults.add(new RegexEntry("Private Key",
                "-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY", true, true));
        defaults.add(new RegexEntry("Generic Secret",
                "(?i)(?:password|secret|apikey|api_key|token|auth)\\s*[=:]\\s*['\"]?[a-zA-Z0-9_\\-]{16,}['\"]?", true, true));

        // --- PaaS ---
        defaults.add(new RegexEntry("Heroku API Key",
                "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", false, false));

        return defaults;
    }

    /** Save the given regex entries to disk. */
    public void save(List<RegexEntry> entries) {
        try {
            configFile.getParentFile().mkdirs();
            ZapXmlConfiguration config = new ZapXmlConfiguration();
            config.setRootElementName(ROOT_KEY);

            for (int i = 0; i < entries.size(); i++) {
                RegexEntry entry = entries.get(i);
                String key = RULE_KEY + "(" + i + ")";
                config.setProperty(key + "[@name]", entry.getName());
                config.setProperty(key + "[@pattern]", entry.getPattern());
                config.setProperty(key + "[@activeC2S]", entry.isActiveC2S());
                config.setProperty(key + "[@activeS2C]", entry.isActiveS2C());
            }

            config.save(configFile);
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save regex rules to {}", configFile.getAbsolutePath(), e);
        }
    }
}
