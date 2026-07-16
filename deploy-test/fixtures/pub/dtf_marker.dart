/// Marker library for the Artifact Keeper format-conformance pub (Dart) leg.
///
/// The [dtfMarker] string is grep-able so the conformance plugin can prove that
/// a REAL `dart pub get` fetched the advertised archive from AK, verified its
/// `archive_sha256`, and unpacked it into the pub cache (not merely that the
/// package listing advertised a version).
library dtf_marker;

/// The grep-able install marker.
const String dtfMarker = 'DTF-PUB-INSTALLED-1.0.0';

/// Trivial API so a consumer can `import 'package:dtf_marker/dtf_marker.dart';`
/// and link against it.
String marker() => dtfMarker;
