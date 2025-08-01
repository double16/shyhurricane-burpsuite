plugins {
    id("java")
    id("com.gradleup.shadow") version "8.3.5"
    id("com.diffplug.spotless") version "7.2.1"
    id("com.github.ben-manes.versions") version "0.52.0"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.+")
    implementation("org.apache.commons:commons-lang3:3.18.+")
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.7")
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName.set("ShyHurricaneForwarder")
    archiveClassifier.set("")
    minimize()
}
