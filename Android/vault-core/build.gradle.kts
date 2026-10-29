// Pure Kotlin reader for the v2 vault format (Docs/V2-VAULT-FORMAT-SPEC.md).
// No Android dependency: the app hands it a libsodium binding, and the JVM
// tests use lazysodium-java against the committed fixture vault and vectors.
plugins {
    kotlin("jvm")
}

// Java 17 bytecode, the level Android builds use.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("com.goterl:lazysodium-java:5.1.4")
    testImplementation("net.java.dev.jna:jna:5.14.0")
}

tasks.test {
    useJUnitPlatform()
    systemProperty(
        "hanzala.vectors.dir",
        rootProject.file("../Tests/HanzalaomatorCoreTests/Fixtures/v2-format-vectors").absolutePath,
    )
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
