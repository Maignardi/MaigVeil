package com.maignardi.maigveil

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.maignardi.maigveil.protected_core.ProtectedVaultEngine
import com.maignardi.maigveil.ui.theme.MaigVeilTheme
import io.github.maignardi.maigveil.runtime.MaigVeil
import io.github.maignardi.maigveil.runtime.MaigVeilAssets
import io.github.maignardi.maigveil.runtime.MaigVeilStatus

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        MaigVeil.init(this)
        enableEdgeToEdge()
        setContent {
            MaigVeilTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    MaigVeilDashboard(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

@Composable
fun MaigVeilDashboard(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var status by remember { mutableStateOf(MaigVeil.status()) }
    var outputLog by remember {
        mutableStateOf("MaigVeil C++20 engine ready. Tap any shield layer below to verify and benchmark.")
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = "MaigVeil Binary Shield",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "Multi-Pass ASM 9 + Native C++20 Polymorphic VM & White-Box Engine",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        StatusCard(status)

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                modifier = Modifier.weight(1f),
                onClick = {
                    val t0 = System.nanoTime()
                    val masked = ProtectedVaultEngine.getMaskedApiKey()
                    val saltHash = ProtectedVaultEngine.digestSha256Hex(ProtectedVaultEngine.HMAC_SALT)
                    val dtUs = (System.nanoTime() - t0) / 1000.0
                    outputLog = buildString {
                        appendLine("[Pass 1 + Pass 3: ARX Strings & INVOKEDYNAMIC]")
                        appendLine("Masked const val: $masked")
                        appendLine("SHA-256 (via INVOKEDYNAMIC): ${saltHash.take(24)}...")
                        appendLine("Latency: ${"%.2f".format(dtUs)} us")
                    }
                }
            ) {
                Text("Strings & Indy")
            }

            Button(
                modifier = Modifier.weight(1f),
                onClick = {
                    val t0 = System.nanoTime()
                    val vmRes = ProtectedVaultEngine.computeLicenseChecksum(42_007, 1337)
                    val t1 = System.nanoTime()
                    val jvmRes = ProtectedVaultEngine.baselineComputeLicenseChecksum(42_007, 1337)
                    val t2 = System.nanoTime()
                    val risk = ProtectedVaultEngine.evaluateRiskScore(12_000, 4, 2)
                    outputLog = buildString {
                        appendLine("[Pass 2 + Pass 4: CFF & C++20 Polymorphic VM]")
                        appendLine("VM Checksum: $vmRes (matches JVM baseline: ${vmRes == jvmRes})")
                        appendLine("VM Latency: ${"%.2f".format((t1 - t0) / 1000.0)} us vs JVM: ${"%.2f".format((t2 - t1) / 1000.0)} us")
                        appendLine("CFF + Opaque Predicates Risk Score: $risk / 100")
                    }
                }
            ) {
                Text("VM & CFF")
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                modifier = Modifier.weight(1f),
                onClick = {
                    val t0 = System.nanoTime()
                    val json = MaigVeilAssets.open(context, "config/secret_config.json")
                        .bufferedReader().use { it.readText() }
                    val pem = MaigVeilAssets.open(context, "certs/pinned_root.pem")
                        .bufferedReader().use { it.readText() }
                    val dtUs = (System.nanoTime() - t0) / 1000.0
                    outputLog = buildString {
                        appendLine("[Pass 5: ChaCha20-Poly1305 Asset Shield]")
                        appendLine("Decrypted config/secret_config.json (${json.length} B):")
                        appendLine(json.trim())
                        appendLine("Decrypted certs/pinned_root.pem: ${pem.lines().firstOrNull()}")
                        appendLine("Latency: ${"%.2f".format(dtUs)} us")
                    }
                }
            ) {
                Text("Asset Shield")
            }

            OutlinedButton(
                modifier = Modifier.weight(1f),
                onClick = {
                    val t0 = System.nanoTime()
                    val zeroTraceLen = MaigVeil.withSecret(1) { buf ->
                        buf.length
                    }
                    val dtUs = (System.nanoTime() - t0) / 1000.0
                    status = MaigVeil.status()
                    outputLog = buildString {
                        appendLine("[Zero-Trace mmap/mlock & Anti-Tamper]")
                        appendLine("Transient secret length: $zeroTraceLen chars (wiped & munmapped)")
                        appendLine("Latency: ${"%.2f".format(dtUs)} us")
                        appendLine("Health: ${if (status.isHealthy) "HEALTHY" else "ALERT"}")
                    }
                }
            ) {
                Text("Zero-Trace")
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Text(
                text = outputLog,
                modifier = Modifier.padding(12.dp),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
private fun StatusCard(status: MaigVeilStatus) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = "Native Self-Defense Telemetry",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(Modifier.height(2.dp))
            Text("Vault Authenticated (APK Sig v2/v3): ${status.vaultAuthenticated}", style = MaterialTheme.typography.bodySmall)
            Text(".text Section Integrity: ${status.textIntegrityOk}", style = MaterialTheme.typography.bodySmall)
            Text("No Inline Hook Trampolines: ${status.noInlineHooks}", style = MaterialTheme.typography.bodySmall)
            Text("No Debugger (TracerPid == 0): ${status.noDebuggerAttached}", style = MaterialTheme.typography.bodySmall)
            Text("Protected Strings: ${status.protectedStringCount} | VM Methods: ${status.virtualizedMethodCount}", style = MaterialTheme.typography.bodySmall)
        }
    }
}
