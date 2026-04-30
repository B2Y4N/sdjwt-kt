import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "io.github.b2y4n"
version = "1.0.0-alpha"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.withType<KotlinCompile> {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

dependencies {
    api(libs.kotlinx.serialization.json)
    api(libs.nimbus.jose.jwt)
    api(libs.bouncycastle)

    testImplementation(kotlin("test"))
}

mavenPublishing {
    configure(
        KotlinJvm(
            javadocJar = JavadocJar.Empty(),
            sourcesJar = true,
        ),
    )

    publishToMavenCentral()

    signAllPublications()

    coordinates(group.toString(), "sdjwt-kt", version.toString())

    pom {
        name = "SD-JWT Kotlin"
        description = "A Kotlin library for issuing, verifying, and presenting SD-JWT."
        inceptionYear = "2026"
        url = "https://github.com/B2Y4N/sdjwt-kt"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                id = "b2y4n"
                name = "Bryan Chew"
                url = "https://github.com/B2Y4N"
            }
        }
        scm {
            url = "https://github.com/B2Y4N/sdjwt-kt"
            connection = "scm:git:git://github.com/B2Y4N/sdjwt-kt.git"
            developerConnection = "scm:git:ssh://github.com/B2Y4N/sdjwt-kt.git"
        }
    }
}
