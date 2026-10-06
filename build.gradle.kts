plugins {
    id("java")
    id("com.gradleup.shadow") version "9.6.1"
    id("com.diffplug.spotless") version "8.10.3"
    id("com.github.ben-manes.versions") version "0.64.0"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.+")
    implementation("org.apache.commons:commons-lang3:3.20.+")
    implementation("net.portswigger.burp.extensions:montoya-api:2026.7")
    testImplementation(platform("org.junit:junit-bom:5.11.+"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName.set("ShyHurricaneForwarder")
    archiveClassifier.set("")
    minimize()
}
