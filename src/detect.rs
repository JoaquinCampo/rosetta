use crate::detectors;

/// A single detection result from a detector
pub struct Detection {
    /// What format was detected (e.g., "JWT Token", "Unix Timestamp")
    pub label: String,
    /// Confidence from 0.0 to 1.0
    pub confidence: f64,
    /// Key-value pairs of decoded information
    pub fields: Vec<(String, String)>,
}

/// Run all detectors against the input, returning results sorted by confidence
pub fn run_all(input: &str) -> Vec<Detection> {
    let all_detectors: Vec<fn(&str) -> Option<Detection>> = vec![
        detectors::jwt::detect,
        detectors::base64::detect,
        detectors::unix_timestamp::detect,
        detectors::uuid::detect,
        detectors::cron::detect,
        detectors::ip::detect,
        detectors::cidr::detect,
        detectors::color::detect,
        detectors::semver::detect,
        detectors::http_status::detect,
        detectors::permissions::detect,
        detectors::url::detect,
        detectors::url_encoded::detect,
        detectors::hex::detect,
        detectors::hash::detect,
        detectors::datetime::detect,
        detectors::docker_image::detect,
        detectors::duration::detect,
    ];

    let mut results: Vec<Detection> = all_detectors
        .iter()
        .filter_map(|detector| detector(input))
        .collect();

    // Sort by confidence descending
    results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

    results
}
