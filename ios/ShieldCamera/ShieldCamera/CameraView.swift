import SwiftUI
import AVFoundation

struct CameraView: UIViewControllerRepresentable {
    let onPhoto: (Data) -> Void
    let onCancel: () -> Void

    func makeUIViewController(context: Context) -> CameraVC {
        let vc = CameraVC()
        vc.onPhoto = onPhoto
        vc.onCancel = onCancel
        return vc
    }
    func updateUIViewController(_ uiViewController: CameraVC, context: Context) {}
}

final class CameraVC: UIViewController, AVCapturePhotoCaptureDelegate {
    private let session = AVCaptureSession()
    private let output = AVCapturePhotoOutput()
    private var preview: AVCaptureVideoPreviewLayer!
    private var camera: AVCaptureDevice?
    private var captureButton: UIButton!
    private var flashButton: UIButton!
    private var busy = false

    var onPhoto: ((Data) -> Void)?
    var onCancel: (() -> Void)?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureControls()
        configureCamera()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
        captureButton?.frame = CGRect(x: 30, y: view.bounds.height - 100, width: view.bounds.width - 60, height: 60)
        flashButton?.frame = CGRect(x: 20, y: view.safeAreaInsets.top + 12, width: 70, height: 44)
    }

    private func configureControls() {
        let cancel = UIButton(type: .system)
        cancel.setTitle("Cancel", for: .normal)
        cancel.tintColor = .white
        cancel.addTarget(self, action: #selector(cancelCapture), for: .touchUpInside)
        cancel.frame = CGRect(x: view.bounds.width - 90, y: view.safeAreaInsets.top + 12, width: 70, height: 44)
        cancel.autoresizingMask = [.flexibleLeftMargin]
        view.addSubview(cancel)

        flashButton = UIButton(type: .system)
        flashButton.setTitle("Flash", for: .normal)
        flashButton.tintColor = .white
        flashButton.backgroundColor = UIColor.black.withAlphaComponent(0.55)
        flashButton.layer.cornerRadius = 10
        flashButton.addTarget(self, action: #selector(toggleFlash), for: .touchUpInside)
        view.addSubview(flashButton)

        captureButton = UIButton(type: .system)
        captureButton.setTitle("CAPTURE", for: .normal)
        captureButton.titleLabel?.font = .boldSystemFont(ofSize: 18)
        captureButton.tintColor = .white
        captureButton.backgroundColor = UIColor.black.withAlphaComponent(0.65)
        captureButton.layer.cornerRadius = 12
        captureButton.addTarget(self, action: #selector(capture), for: .touchUpInside)
        captureButton.autoresizingMask = [.flexibleTopMargin, .flexibleWidth]
        view.addSubview(captureButton)
    }

    private func configureCamera() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            setupSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted { self?.setupSession() }
                    else { self?.showCameraDenied() }
                }
            }
        default:
            showCameraDenied()
        }
    }

    private func setupSession() {
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input), session.canAddOutput(output) else {
            showCameraDenied(message: "Shield could not access the rear camera.")
            return
        }
        camera = device
        session.beginConfiguration()
        session.sessionPreset = .photo
        session.addInput(input)
        session.addOutput(output)
        if #available(iOS 16.0, *) { output.maxPhotoQualityPrioritization = .quality }
        session.commitConfiguration()

        preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        view.layer.insertSublayer(preview, at: 0)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.session.startRunning() }
    }

    @objc private func capture() {
        guard !busy, session.isRunning else { return }
        busy = true
        captureButton.isEnabled = false
        let settings = AVCapturePhotoSettings()
        settings.flashMode = .off
        if let camera, camera.hasFlash, flashButton.accessibilityValue == "on" { settings.flashMode = .on }
        output.capturePhoto(with: settings, delegate: self)
    }

    @objc private func toggleFlash() {
        guard let camera, camera.hasTorch else { return }
        flashButton.accessibilityValue = flashButton.accessibilityValue == "on" ? "off" : "on"
        flashButton.setTitle(flashButton.accessibilityValue == "on" ? "Flash On" : "Flash", for: .normal)
    }

    @objc private func cancelCapture() {
        session.stopRunning()
        onCancel?()
    }

    func photoOutput(_ output: AVCapturePhotoOutput, didFinishProcessingPhoto photo: AVCapturePhoto, error: Error?) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.busy = false
            self.captureButton.isEnabled = true
            guard error == nil, let data = photo.fileDataRepresentation(), !data.isEmpty else { return }
            self.onPhoto?(data)
        }
    }

    private func showCameraDenied(message: String = "Camera permission is required for Shield capture.") {
        let label = UILabel(frame: .zero)
        label.text = message
        label.textColor = .white
        label.textAlignment = .center
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24)
        ])
    }
}
