import Foundation
import CoreLocation
@MainActor final class LocationProvider:NSObject,ObservableObject,CLLocationManagerDelegate{private let manager=CLLocationManager();@Published var location:CLLocation?;override init(){super.init();manager.delegate=self;manager.desiredAccuracy=kCLLocationAccuracyBest};func start(){manager.requestWhenInUseAuthorization();manager.startUpdatingLocation()};func locationManager(_ manager:CLLocationManager,didUpdateLocations l:[CLLocation]){location=l.last}}
