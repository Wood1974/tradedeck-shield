plugins { id("com.android.application"); id("org.jetbrains.kotlin.android"); id("org.jetbrains.kotlin.plugin.compose") }

android { namespace = "com.tradedeck.shield"; compileSdk = 35
    buildFeatures { buildConfig = true; compose = true }
    val shieldCloudProjectNumber = (project.findProperty("SHIELD_CLOUD_PROJECT_NUMBER") as String?) ?: "0"
    defaultConfig {
        applicationId = "com.tradedeck.shield"; minSdk = 26; targetSdk = 35; versionCode = 1; versionName = "1.0.0"
        buildConfigField("long", "SHIELD_CLOUD_PROJECT_NUMBER", shieldCloudProjectNumber)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.compose.ui:ui:1.7.6")
    implementation("androidx.compose.material3:material3:1.3.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("io.coil-kt:coil-compose:2.7.0")
    implementation("com.google.android.play:integrity:1.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
