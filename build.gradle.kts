import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    id("java-library")
    alias(libs.plugins.spotless)
    alias(libs.plugins.lombok)
    alias(libs.plugins.zaproxy.addon)
    alias(libs.plugins.zaproxy.common)
}

description = "Decodes and displays Blazor Pack messages sent over WebSockets in pretty-printed JSON."

zapAddOn {
    addOnName.set("Crimson Blazor Decoder")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        zapVersion.set("2.17.0")
        author.set("Renico Koen / CrimsonWall")
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

}

repositories {
    mavenCentral()
}

group = "org.zaproxy.addon"

configure<JavaPluginExtension> {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs = options.compilerArgs + "-Xlint:processing"
    options.compilerArgs = options.compilerArgs - "-Werror"
}

dependencies {
    compileOnly("org.zaproxy:zap:2.17.0")
    compileOnly(files("../zap-extensions/addOns/websocket/build/libs/websocket-37.jar"))
    compileOnly("biz.aQute.bnd:biz.aQute.bnd.annotation:7.2.3")
    compileOnly("com.google.code.findbugs:findbugs-annotations:3.0.1")
}

spotless {
    java {
        clearSteps()
        licenseHeader(
            """
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
            """.trimIndent(),
        )
    }
}
