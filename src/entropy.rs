use std::collections::HashMap;

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn repeated_char_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaaa"), 0.0);
    }

    #[test]
    fn high_entropy_string() {
        let entropy = shannon_entropy("aB3$kL9!mZ2@pQ7&");
        assert!(entropy >= 4.0, "Expected >= 4.0, got {entropy}");
    }

    #[test]
    fn known_entropy_two_chars() {
        let entropy = shannon_entropy("ab");
        assert!((entropy - 1.0).abs() < 0.001);
    }
}
