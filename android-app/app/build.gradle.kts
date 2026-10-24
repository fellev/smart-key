import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.smart_key"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.smartkey.app"
        minSdk = 36
        targetSdk = 37
        versionCode = 3
        versionName = "1.0.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            val keystoreProperties = Properties().apply {
                val propertiesFile = project.file("keystore.properties")
                if (propertiesFile.isFile) {
                    propertiesFile.inputStream().use { load(it) }
                }
            }
            val keystorePath = project.findProperty("KEYSTORE_FILE") as? String
                ?: System.getenv("KEYSTORE_FILE")
                ?: keystoreProperties.getProperty("storeFile")
            val kPassword = project.findProperty("KEYSTORE_PASSWORD") as? String
                ?: System.getenv("KEYSTORE_PASSWORD")
                ?: keystoreProperties.getProperty("storePassword")
            val alias = project.findProperty("KEY_ALIAS") as? String
                ?: System.getenv("KEY_ALIAS")
                ?: keystoreProperties.getProperty("keyAlias")
            val keyPass = project.findProperty("KEY_PASSWORD") as? String
                ?: System.getenv("KEY_PASSWORD")
                ?: keystoreProperties.getProperty("keyPassword")

            if (keystorePath != null && kPassword != null && alias != null && keyPass != null) {
                storeFile = file(keystorePath)
                storePassword = kPassword
                keyAlias = alias
                keyPassword = keyPass
            }
        }
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        viewBinding = true
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            // The protocol and handshake classes only touch android.util.Log,
            // so stubbed defaults are enough to run them on the plain JVM.
            isReturnDefaultValues = true
            // The protocol unit tests read the shared golden vectors from
            // ../../shared-protocols/test-vectors; see SharedVectors.kt.
            all {
                it.systemProperty(
                    "smartkey.sharedProtocols",
                    rootProject.file("../shared-protocols").absolutePath
                )
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.navigation.fragment.ktx)
    implementation(libs.androidx.navigation.ui.ktx)
    implementation(libs.material)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.lifecycle.service)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.security.crypto)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
}