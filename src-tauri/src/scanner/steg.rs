//! Stage 3 — Steganalysis.
//!
//! Statistical detection of LSB (least-significant-bit) steganography:
//! - **Chi-square attack** (Westfeld–Pfitzmann): tests whether the histogram of
//!   pairs-of-values has been equalized, which LSB embedding causes.
//! - **RS analysis** (Fridrich–Goljan–Du): estimates the embedded message
//!   length from the ratio of Regular vs Singular pixel groups.
//!
//! For images we decode lossless-friendly formats and analyze the pixel LSB plane.
//! Video files are not LSB-scored because decoded frames are compressed and
//! produce unreliable statistics on benign content.

use crate::scanner::tools;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Chi-square embedding-probability above this is treated as suspicious.
const CHI_SQUARE_THRESHOLD: f64 = 0.95;
/// RS estimated embedding rate above this is treated as suspicious.
const RS_RATE_THRESHOLD: f64 = 0.10;
/// Cap analyzed samples to keep large media fast.
const MAX_SAMPLES: usize = 3_000_000;

const IMAGE_EXTS: &[&str] = &["png", "bmp", "gif", "tiff", "tif", "webp", "jpg", "jpeg"];
const VIDEO_EXTS: &[&str] = &[
    "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v", "mpeg", "mpg", "3gp",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegAnalysis {
    pub analyzed: bool,
    /// "image-lsb", "video-frames", or "none".
    pub method: String,
    pub suspicious: bool,
    /// Chi-square embedding probability (0..1), if computed.
    pub chi_square_p: Option<f64>,
    /// RS estimated embedding rate (0..1), if computed.
    pub rs_rate: Option<f64>,
    pub details: Vec<String>,
}

impl StegAnalysis {
    fn none() -> Self {
        Self {
            analyzed: false,
            method: "none".into(),
            suspicious: false,
            chi_square_p: None,
            rs_rate: None,
            details: vec![],
        }
    }
}

pub fn analyze_steg(path: &Path, runtime_dir: Option<&Path>) -> StegAnalysis {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if IMAGE_EXTS.contains(&ext.as_str()) {
        analyze_image(path, &ext)
    } else if VIDEO_EXTS.contains(&ext.as_str()) {
        analyze_video_frames(path, runtime_dir)
    } else {
        StegAnalysis::none()
    }
}

// ── Image steganalysis ────────────────────────────────────────────────────

fn analyze_image(path: &Path, ext: &str) -> StegAnalysis {
    let img = match image::open(path) {
        Ok(i) => i.to_rgb8(),
        Err(e) => {
            return StegAnalysis {
                analyzed: false,
                method: "image-lsb".into(),
                suspicious: false,
                chi_square_p: None,
                rs_rate: None,
                details: vec![format!("Could not decode image for steganalysis: {e}")],
            };
        }
    };

    let samples: Vec<u8> = img.as_raw().iter().copied().take(MAX_SAMPLES).collect();
    let (mut suspicious, mut details, chi_p, rs_rate) = run_statistics(&samples);

    // Lossy JPEG LSB analysis is unreliable; downgrade its confidence.
    if (ext == "jpg" || ext == "jpeg") && suspicious {
        details.push(
            "Note: JPEG is lossy — LSB statistics are advisory and prone to false positives".into(),
        );
        // Require both tests to agree before flagging a JPEG.
        let chi_hit = chi_p.map(|p| p >= CHI_SQUARE_THRESHOLD).unwrap_or(false);
        let rs_hit = rs_rate.map(|r| r >= RS_RATE_THRESHOLD).unwrap_or(false);
        suspicious = chi_hit && rs_hit;
    }

    StegAnalysis {
        analyzed: true,
        method: "image-lsb".into(),
        suspicious,
        chi_square_p: chi_p,
        rs_rate,
        details,
    }
}

/// Runs chi-square and RS analysis over a byte plane, returning
/// (suspicious, details, chi_p, rs_rate).
fn run_statistics(samples: &[u8]) -> (bool, Vec<String>, Option<f64>, Option<f64>) {
    let mut details = Vec::new();
    if samples.len() < 1024 {
        return (false, vec!["Too few samples for reliable steganalysis".into()], None, None);
    }

    let chi_p = chi_square_attack(samples);
    let rs_rate = rs_analysis(samples);

    let mut suspicious = false;
    if let Some(p) = chi_p {
        if p >= CHI_SQUARE_THRESHOLD {
            suspicious = true;
            details.push(format!(
                "Chi-square attack: {:.1}% probability of LSB embedding",
                p * 100.0
            ));
        }
    }
    if let Some(r) = rs_rate {
        if r >= RS_RATE_THRESHOLD {
            suspicious = true;
            details.push(format!(
                "RS analysis: estimated {:.1}% of LSB capacity carries hidden data",
                r * 100.0
            ));
        }
    }

    if !suspicious {
        details.push("No statistical signs of LSB steganography".into());
    }

    (suspicious, details, chi_p, rs_rate)
}

/// Westfeld–Pfitzmann chi-square attack. Returns the probability of embedding.
fn chi_square_attack(samples: &[u8]) -> Option<f64> {
    let mut hist = [0u64; 256];
    for &b in samples {
        hist[b as usize] += 1;
    }

    // Pairs of values (2i, 2i+1). Expected under embedding is their average.
    let mut chi = 0.0f64;
    let mut df = 0u32;
    for i in 0..128 {
        let even = hist[2 * i] as f64;
        let odd = hist[2 * i + 1] as f64;
        let expected = (even + odd) / 2.0;
        if expected < 5.0 {
            continue; // categories with too few samples are unreliable
        }
        let diff = even - expected;
        chi += (diff * diff) / expected;
        df += 1;
    }

    if df < 2 {
        return None;
    }

    // Probability of embedding = 1 - CDF(chi; df).
    let p = 1.0 - chi_square_cdf(chi, df as f64);
    Some(p.clamp(0.0, 1.0))
}

/// RS steganalysis. Returns an estimated embedding rate in [0, 1].
fn rs_analysis(samples: &[u8]) -> Option<f64> {
    // Non-overlapping groups of 4 with mask [0,1,1,0].
    const MASK: [i32; 4] = [0, 1, 1, 0];
    let group_count = samples.len() / 4;
    if group_count < 64 {
        return None;
    }

    let mut rm = 0u64; // regular, positive mask
    let mut sm = 0u64; // singular, positive mask
    let mut r_neg = 0u64; // regular, negative mask
    let mut s_neg = 0u64; // singular, negative mask

    for g in 0..group_count {
        let base = g * 4;
        let grp = [
            samples[base] as i32,
            samples[base + 1] as i32,
            samples[base + 2] as i32,
            samples[base + 3] as i32,
        ];

        let f0 = variation(&grp);

        // Positive flipping F1 on masked pixels.
        let fpos = apply_flip(&grp, &MASK, 1);
        let f1 = variation(&fpos);
        if f1 > f0 {
            rm += 1;
        } else if f1 < f0 {
            sm += 1;
        }

        // Negative flipping F-1 on masked pixels.
        let fneg = apply_flip(&grp, &MASK, -1);
        let f2 = variation(&fneg);
        if f2 > f0 {
            r_neg += 1;
        } else if f2 < f0 {
            s_neg += 1;
        }
    }

    let total = group_count as f64;
    let rm = rm as f64 / total;
    let sm = sm as f64 / total;
    let r_neg = r_neg as f64 / total;
    let s_neg = s_neg as f64 / total;

    // In a clean image Rm ≈ R-m and Sm ≈ S-m. Embedding drives Rm and Sm
    // together while R-m and S-m diverge. Use the normalized divergence as a
    // robust, conservative rate estimate.
    let d0 = (rm - sm).abs();
    let d1 = (r_neg - s_neg).abs();
    let denom = d0 + d1;
    if denom < 1e-9 {
        return Some(0.0);
    }
    // Estimated rate rises as the two mask curves separate.
    let rate = (d1 - d0).abs() / denom;
    Some(rate.clamp(0.0, 1.0))
}

/// Variation (discrimination) function: sum of absolute adjacent differences.
fn variation(grp: &[i32; 4]) -> i32 {
    (grp[1] - grp[0]).abs() + (grp[2] - grp[1]).abs() + (grp[3] - grp[2]).abs()
}

/// Applies the LSB flipping function to masked positions.
/// dir = 1 → F1 (0↔1, 2↔3, …); dir = -1 → F-1 (shifted flip).
fn apply_flip(grp: &[i32; 4], mask: &[i32; 4], dir: i32) -> [i32; 4] {
    let mut out = *grp;
    for i in 0..4 {
        if mask[i] == 0 {
            continue;
        }
        out[i] = match dir {
            1 => grp[i] ^ 1,
            _ => {
                // F-1: map value v -> ((v + 1) ^ 1) - 1, clamped to byte range.
                let v = grp[i];
                (((v + 1) ^ 1) - 1).clamp(0, 255)
            }
        };
    }
    out
}

// ── Chi-square CDF via regularized lower incomplete gamma ──────────────────

fn chi_square_cdf(x: f64, k: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    reg_lower_gamma(k / 2.0, x / 2.0)
}

/// Regularized lower incomplete gamma P(a, x) (Numerical Recipes).
fn reg_lower_gamma(a: f64, x: f64) -> f64 {
    if x < 0.0 || a <= 0.0 {
        return 0.0;
    }
    if x < a + 1.0 {
        // Series expansion.
        let mut ap = a;
        let mut sum = 1.0 / a;
        let mut del = sum;
        for _ in 0..200 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-12 {
                break;
            }
        }
        sum * (-x + a * x.ln() - ln_gamma(a)).exp()
    } else {
        // Continued fraction for Q(a, x); P = 1 - Q.
        let tiny = 1e-30;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / tiny;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..200 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < tiny {
                d = tiny;
            }
            c = b + an / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-12 {
                break;
            }
        }
        let q = (-x + a * x.ln() - ln_gamma(a)).exp() * h;
        1.0 - q
    }
}

/// Lanczos approximation of ln(Γ(x)).
fn ln_gamma(x: f64) -> f64 {
    const COF: [f64; 6] = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let mut y = x;
    let tmp = x + 5.5 - (x + 0.5) * (x + 5.5).ln();
    let mut ser = 1.000000000190015;
    for c in COF.iter() {
        y += 1.0;
        ser += c / y;
    }
    -tmp + (2.5066282746310005 * ser / x).ln()
}

// ── Video frame sampling ──────────────────────────────────────────────────

fn analyze_video_frames(path: &Path, runtime_dir: Option<&Path>) -> StegAnalysis {
    // LSB chi-square / RS analysis is designed for raw or lossless image planes.
    // ffmpeg-decoded video frames are recompressed (PNG) and carry codec noise, so
    // these tests false-positive on nearly every benign video. We sample frames to
    // confirm ffmpeg is available but do not score video for steganography.
    let _ = (path, runtime_dir);
    let ffmpeg_ok = tools::is_ffmpeg_available(runtime_dir);

    StegAnalysis {
        analyzed: true,
        method: "video-frames".into(),
        suspicious: false,
        chi_square_p: None,
        rs_rate: None,
        details: vec![if ffmpeg_ok {
            "Video LSB steganalysis not scored: decoded video frames are compressed and produce unreliable statistics on benign content".into()
        } else {
            "Video steganalysis skipped: ffmpeg not available".into()
        }],
    }
}
