package com.tradedeck.shield

import android.Manifest
import android.content.Context
import android.location.Location
import android.location.LocationManager
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import coil.compose.rememberAsyncImagePainter
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/** Shield captures only fresh CameraX bytes; no gallery import or file picker. */
class MainActivity : ComponentActivity() {
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        if (grants[Manifest.permission.CAMERA] != true) {
            Toast.makeText(this, "Camera permission is required for Shield capture.", Toast.LENGTH_LONG).show()
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        cacheDir.listFiles()?.filter { it.name.startsWith("shield-") && it.name.endsWith(".jpg") }?.forEach { it.delete() }
        val required = arrayOf(Manifest.permission.CAMERA, Manifest.permission.ACCESS_FINE_LOCATION)
        if (required.any { ContextCompat.checkSelfPermission(this,it) != PackageManager.PERMISSION_GRANTED }) permissions.launch(required)
        setContent { Surface { ShieldCameraScreen() } }
    }
}

@Composable
private fun ShieldCameraScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    var baseUrl by remember { mutableStateOf("https://tradedeck-shield.onrender.com") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var session by remember { mutableStateOf<ShieldSession?>(null) }
    var jobId by remember { mutableStateOf("") }
    var pointId by remember { mutableStateOf("") }
    var challenge by remember { mutableStateOf<ShieldChallenge?>(null) }
    var imageCapture by remember { mutableStateOf<ImageCapture?>(null) }
    var camera by remember { mutableStateOf<Camera?>(null) }
    var capturedFile by remember { mutableStateOf<File?>(null) }
    var photoCapturedAt by remember { mutableStateOf<java.time.Instant?>(null) }
    var captureLocation by remember { mutableStateOf<Location?>(null) }
    var locationStated by remember { mutableStateOf("") }
    var purpose by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var takingPhoto by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && challenge != null) {
                capturedFile?.delete()
                capturedFile = null
                photoCapturedAt = null
                captureLocation = null
                challenge = null
                takingPhoto = false
                message = "Capture interrupted. Start again with a new challenge."
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("SHIELD")
        if (session == null) {
            OutlinedTextField(baseUrl, { baseUrl = it }, label = { Text("Shield HTTPS API URL") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(email, { email = it }, label = { Text("Email") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(password, { password = it }, label = { Text("Password") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
            Button(onClick = {
                busy = true
                scope.launch {
                    try { session = ShieldApi(baseUrl).login(email,password); password = ""; message = "Signed in" }
                    catch (e: Exception) { message = "Sign in failed: ${e.message}" }
                    finally { busy = false }
                }
            }, enabled = !busy && email.isNotBlank() && password.isNotBlank()) { Text("Sign in") }
        } else {
            OutlinedTextField(jobId, { jobId = it }, label = { Text("Job ID") }, modifier = Modifier.fillMaxWidth(), enabled = challenge == null)
            OutlinedTextField(pointId, { pointId = it }, label = { Text("Point ID") }, modifier = Modifier.fillMaxWidth(), enabled = challenge == null)
            if (challenge == null) {
                Button(onClick = {
                    busy = true
                    scope.launch {
                        try { challenge = ShieldApi(baseUrl).challenge(session!!,jobId,pointId); message = "Challenge ready" }
                        catch (e: Exception) { message = "Job access denied or unavailable: ${e.message}" }
                        finally { busy = false }
                    }
                }, enabled = !busy && jobId.isNotBlank() && pointId.isNotBlank()) { Text("Start capture") }
            } else if (capturedFile == null) {
                CameraPreview(modifier = Modifier.fillMaxWidth().weight(1f), onReady = { capture, active ->
                    imageCapture = capture; camera = active
                }, onError = { message = it })
                Spacer(Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    OutlinedButton(onClick = { camera?.cameraControl?.enableTorch(camera?.cameraInfo?.torchState?.value != 1) }) { Text("Flash") }
                    Button(onClick = {
                        val capture = imageCapture ?: return@Button
                        takingPhoto = true
                        val file = File(context.cacheDir,"shield-${System.nanoTime()}.jpg")
                        capture.takePicture(ImageCapture.OutputFileOptions.Builder(file).build(), ContextCompat.getMainExecutor(context),
                            object : ImageCapture.OnImageSavedCallback {
                                override fun onError(exception: ImageCaptureException) {
                                    file.delete()
                                    takingPhoto = false
                                    message = "Capture failed: ${exception.message}"
                                }
                                override fun onImageSaved(output: ImageCapture.OutputFileResults) {
                                    if (challenge == null || !lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                        file.delete()
                                        takingPhoto = false
                                        return
                                    }
                                    takingPhoto = false
                                    photoCapturedAt = java.time.Instant.now()
                                    captureLocation = lastKnownSiteFix(context)
                                    capturedFile = file
                                }
                            })
                    }, enabled = !busy && !takingPhoto && imageCapture != null) { Text("CAPTURE") }
                }
            } else {
                Image(painter = rememberAsyncImagePainter(capturedFile), contentDescription = "Fresh Shield capture",
                    modifier = Modifier.fillMaxWidth().weight(1f))
                OutlinedTextField(locationStated, { locationStated = it }, label = { Text("Where is this photo from?") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(purpose, { purpose = it }, label = { Text("What does it document?") }, modifier = Modifier.fillMaxWidth())
                Text("These statements are yours; Shield does not infer them from location data.")
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    OutlinedButton(onClick = { capturedFile?.delete(); capturedFile = null; photoCapturedAt = null; captureLocation = null; challenge = null }) { Text("Retake") }
                    Button(onClick = {
                        val original = capturedFile?.readBytes() ?: return@Button
                        val active = session ?: return@Button
                        val current = challenge ?: return@Button
                        val capturedAt = photoCapturedAt ?: return@Button
                        busy = true
                        scope.launch {
                            try {
                                val integrity = ShieldPlayIntegrityClient(context,BuildConfig.SHIELD_CLOUD_PROJECT_NUMBER)
                                val evidence = ShieldApi(baseUrl).capture(active,jobId,current,original,capturedAt,locationStated,purpose,captureLocation,integrity)
                                message = "SEALED — evidence ID: $evidence"
                                capturedFile?.delete(); capturedFile = null; photoCapturedAt = null; captureLocation = null; challenge = null
                                locationStated = ""; purpose = ""
                            } catch (e: Exception) { message = "Seal failed: ${e.message}" }
                            finally { busy = false }
                        }
                    }, enabled = !busy && locationStated.isNotBlank() && purpose.isNotBlank()) { Text("Seal") }
                }
            }
            OutlinedButton(onClick = { session = null; capturedFile?.delete(); capturedFile = null; photoCapturedAt = null; captureLocation = null; challenge = null }) { Text("Sign out") }
        }
        Text(message)
    }
}

private fun lastKnownSiteFix(context: Context): Location? {
    if (ContextCompat.checkSelfPermission(context,Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED &&
        ContextCompat.checkSelfPermission(context,Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) return null
    val manager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
    return try {
        listOf(LocationManager.GPS_PROVIDER,LocationManager.NETWORK_PROVIDER)
            .mapNotNull { provider -> if (manager.isProviderEnabled(provider)) manager.getLastKnownLocation(provider) else null }
            .maxByOrNull { it.time }?.let { Location(it) }
    } catch (_: SecurityException) { null }
}

@Composable
private fun CameraPreview(modifier: Modifier, onReady: (ImageCapture,Camera) -> Unit, onError: (String) -> Unit) {
    val disposed = remember { AtomicBoolean(false) }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    DisposableEffect(Unit) {
        onDispose {
            disposed.set(true)
            provider?.unbindAll()
        }
    }
    AndroidView(modifier = modifier, factory = { context ->
        PreviewView(context).also { view ->
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener({
                try {
                    if (disposed.get()) return@addListener
                    val activeProvider = future.get()
                    provider = activeProvider
                    val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                    val capture = ImageCapture.Builder().setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
                        .setJpegQuality(100).build()
                    activeProvider.unbindAll()
                    val active = activeProvider.bindToLifecycle(context as LifecycleOwner,CameraSelector.DEFAULT_BACK_CAMERA,preview,capture)
                    onReady(capture,active)
                } catch (e: Exception) { onError("Camera unavailable: ${e.message}") }
            },ContextCompat.getMainExecutor(context))
        }
    })
}

data class ShieldAttestationSheet(val locationStated: String, val purpose: String) {
    fun validate(): ShieldAttestationSheet {
        require(locationStated.trim().isNotEmpty() && locationStated.trim().length <= 500) { "Invalid location statement" }
        require(purpose.trim().isNotEmpty() && purpose.trim().length <= 1000) { "Invalid purpose statement" }
        return ShieldAttestationSheet(locationStated.trim(),purpose.trim())
    }
}
