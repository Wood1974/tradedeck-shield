import SwiftUI
import CryptoKit
import CoreLocation

struct ContentView: View {
    @StateObject private var state = AppState()
    @StateObject private var location = LocationProvider()
    @Environment(\.scenePhase) private var scenePhase
    private let attest = AppAttestManager()
    @State private var email = ""
    @State private var password = ""
    @State private var challenge: Challenge?
    @State private var photo: Data?
    @State private var photoCapturedAt: Date?
    @State private var capturedLocation: CLLocation?
    @State private var locationStated = ""
    @State private var purpose = ""
    @State private var camera = false
    @State private var busy = false
    @State private var result = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    Text("SHIELD").font(.largeTitle.bold())
                    if state.token.isEmpty {
                        TextField("Shield HTTPS API URL", text: $state.apiBaseURL)
                            .textInputAutocapitalization(.never).textFieldStyle(.roundedBorder)
                        TextField("Email", text: $email)
                            .textInputAutocapitalization(.never).keyboardType(.emailAddress).textFieldStyle(.roundedBorder)
                        SecureField("Password", text: $password).textFieldStyle(.roundedBorder)
                        Button("Sign in") { Task { await signIn() } }
                            .disabled(busy || email.isEmpty || password.isEmpty)
                    } else {
                        TextField("Job ID", text: $state.jobID).textFieldStyle(.roundedBorder)
                            .disabled(challenge != nil)
                        TextField("Point ID", text: $state.pointID).textFieldStyle(.roundedBorder)
                            .disabled(challenge != nil)
                        if let photo, let image = UIImage(data: photo) {
                            Image(uiImage: image).resizable().scaledToFit().frame(maxHeight: 250)
                            Text("Photo SHA-256 \(sha256Hex(photo).prefix(16))…").font(.caption.monospaced())
                        }
                        Button(photo == nil ? "Open camera" : "Retake photo") { Task { await begin() } }
                            .disabled(busy || state.jobID.isEmpty || state.pointID.isEmpty)
                        if photo != nil {
                            Text("Required attestation").font(.headline)
                            TextField("Where is this / location or context", text: $locationStated, axis: .vertical).textFieldStyle(.roundedBorder)
                            TextField("Why are you taking this photo / what does it document", text: $purpose, axis: .vertical).textFieldStyle(.roundedBorder)
                            Text("These are your statements. Shield does not fill them from GPS or job data.")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Seal photo and attestation") { Task { await seal() } }
                                .disabled(locationStated.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                                          purpose.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || busy)
                        }
                        Button("Sign out") { discardCapture(); state.token = ""; state.accountID = "" }
                    }
                    Text(result).font(.footnote.monospaced()).textSelection(.enabled)
                }.padding().navigationTitle("Capture")
            }
        }
        .sheet(isPresented: $camera) {
            CameraView(onPhoto: {
                photo = $0
                photoCapturedAt = Date()
                capturedLocation = location.location
                camera = false
            }, onCancel: { discardCapture() }).ignoresSafeArea()
        }
        .task { location.start() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background && (camera || photo != nil) {
                discardCapture()
                result = "Capture interrupted. Start again with a new challenge."
            }
        }
    }

    private func api() throws -> ShieldAPI {
        guard let base = URL(string: state.apiBaseURL), base.scheme == "https" else { throw URLError(.badURL) }
        return ShieldAPI(base: base, token: state.token.isEmpty ? nil : state.token)
    }

    private func discardCapture() {
        camera = false
        photo = nil
        photoCapturedAt = nil
        capturedLocation = nil
        challenge = nil
        locationStated = ""
        purpose = ""
    }

    private func signIn() async {
        busy = true; defer { busy = false }
        do {
            let response = try await api().login(email: email, password: password)
            state.accountID = response.account_id
            state.token = response.access_token
            password = ""
            result = "Signed in"
        } catch { result = "Sign in failed: \(error)" }
    }

    private func begin() async {
        busy = true; defer { busy = false }
        do {
            discardCapture()
            challenge = try await api().challenge(jobID: state.jobID, pointID: state.pointID, accountID: state.accountID)
            camera = true
        } catch { result = "Challenge failed: \(error)" }
    }

    private func seal() async {
        guard let photo, let photoCapturedAt, let challenge else { return }
        busy = true; defer { busy = false }
        do {
            let photoHash = sha256Hex(photo)
            let noteHash = sha256Hex(canonicalNote(locationStated: locationStated, purpose: purpose))
            let bind = bindHash(photo: photoHash, note: noteHash, job: state.jobID,
                                point: state.pointID, nonce: challenge.nonce, account: state.accountID)
            let client = try api()
            try await attest.ensureAttested(accountID: state.accountID, api: client)
            let assertion = try await attest.assertion(accountID: state.accountID,
                                                       clientDataHash: Data(SHA256.hash(data: Data(bind.utf8))))
            let fix = capturedLocation
            let position = fix.map { ($0.coordinate.latitude, $0.coordinate.longitude, $0.horizontalAccuracy) }
            let observedAt = fix.map { ISO8601DateFormatter().string(from: $0.timestamp) }
            let simulated = fix?.sourceInformation?.isSimulatedBySoftware == true ? true : nil
            let response = try await client.capture(jobID: state.jobID, challenge: challenge, accountID: state.accountID,
                                                    photo: photo, locationStated: locationStated, purpose: purpose,
                                                    capturedAt: ISO8601DateFormatter().string(from: photoCapturedAt),
                                                    location: position, locationObservedAt: observedAt, mockFlag: simulated, attestation: assertion)
            discardCapture()
            result = "SEALED\nEvidence ID: \(response.evidence_id)\nBind: \(response.bind_hash)\nServer time: \(response.written_at)"
        } catch { result = "Seal failed: \(error)" }
    }
}
