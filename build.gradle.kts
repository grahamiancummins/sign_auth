plugins {
    kotlin("jvm") version "2.3.0"
}

group = "com.symbolscope"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

val ktorVersion = "2.3.13"

dependencies {
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:2.2.21")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.8.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.0.3")
    testImplementation(kotlin("test"))

    // Ktor client (upstream forwarding)
    implementation("io.ktor:ktor-client-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-cio-jvm:$ktorVersion")

    // Ktor server
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-cio-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages-jvm:$ktorVersion")

    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.16.1")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.16.1")
    implementation("org.bouncycastle:bcpg-jdk18on:1.83")
    implementation("org.pgpainless:pgpainless-core:2.0.2")
}

kotlin {
    jvmToolchain(25)
}

tasks.test {
    useJUnitPlatform()
}
