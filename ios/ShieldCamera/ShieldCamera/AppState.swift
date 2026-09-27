import Foundation
import SwiftUI
@MainActor final class AppState: ObservableObject { @Published var accountID=""; @Published var token=""; @Published var apiBaseURL="https://"; @Published var jobID=""; @Published var pointID="" }
