import org.zaproxy.gradle.addon.AddOnStatus

description = "Decodes and displays Blazor Pack messages sent over WebSockets in pretty-printed JSON."

zapAddOn {
    addOnName.set("Crimson Blazor Decoder")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        zapVersion.set("2.17.0")
        author.set("CrimsonWall")
        url.set("https://github.com/crimsonwall/crimsonblazordecoder")
        extensions {
            register("com.crimsonwall.crimsonblazordecoder.ExtensionCrimsonBlazorDecoder")
        }
        dependencies {
            addOns {
                register("websocket") {
                    version.set(">= 0.1.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("com.crimsonwall.crimsonblazordecoder.CrimsonBlazorDecoderAPI")
        messages.set(file("src/main/resources/com/crimsonwall/crimsonblazordecoder/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("websocket")

    rootProject.findProject(":testutils")?.let { testImplementation(it) }
}

configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        // Override the default ZAP license header with our own.
        clearSteps()
        licenseHeader(
            """
            /*
             * Crimson Blazor Decoder - Blazor Pack Decoder for OWASP ZAP.
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
            """.trimIndent(),
        )
    }
}
