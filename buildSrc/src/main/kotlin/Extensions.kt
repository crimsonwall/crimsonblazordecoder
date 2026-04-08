import org.gradle.api.artifacts.dsl.DependencyHandler

/**
 * Adds an add-on project as a dependency.
 * In this standalone context the websocket jar is provided via compileOnly
 * in the root build.gradle.kts, so this is a no-op.
 */
fun DependencyHandler.zapAddOn(addOnId: String) {
    // no-op: compile dependency handled by root build
}
