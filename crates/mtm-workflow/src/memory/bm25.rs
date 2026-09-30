use std::collections::{BTreeMap, BTreeSet};

pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub fn rank(query: &str, documents: &[String]) -> Vec<usize> {
    let terms = tokenize(query);
    let tokenized = documents
        .iter()
        .map(|document| tokenize(document))
        .collect::<Vec<_>>();
    let mut frequencies = BTreeMap::new();
    for token in &terms {
        *frequencies.entry(token.clone()).or_insert(0_u32) += 1;
    }
    let mut document_frequency = BTreeMap::new();
    for tokens in &tokenized {
        for token in tokens.iter().collect::<BTreeSet<_>>() {
            *document_frequency.entry(token.clone()).or_insert(0_usize) += 1;
        }
    }
    let average = if tokenized.is_empty() {
        0.0
    } else {
        tokenized.iter().map(Vec::len).sum::<usize>() as f64 / tokenized.len() as f64
    };
    let mut scored = tokenized
        .iter()
        .enumerate()
        .map(|(index, tokens)| {
            let mut counts = BTreeMap::new();
            for token in tokens {
                *counts.entry(token).or_insert(0_u32) += 1;
            }
            let length = tokens.len() as f64;
            let norm = if average > 0.0 {
                1.5 * (0.25 + 0.75 * length / average)
            } else {
                1.5
            };
            let score = frequencies
                .iter()
                .map(|(token, query_tf)| {
                    let tf = f64::from(*counts.get(token).unwrap_or(&0));
                    if tf == 0.0 {
                        return 0.0;
                    }
                    let df = *document_frequency.get(token).unwrap_or(&0) as f64;
                    let n = documents.len() as f64;
                    let idf = (1.0 + (n - df + 0.5) / (df + 0.5)).ln();
                    f64::from(*query_tf) * idf * (tf * 2.5) / (tf + norm)
                })
                .sum::<f64>();
            (index, score)
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored.into_iter().map(|item| item.0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn related_text_ranks_first_and_ties_are_stable() {
        let docs = vec![
            "algebraic geometry".to_owned(),
            "number theory".to_owned(),
            "algebraic geometry".to_owned(),
        ];
        assert_eq!(rank("geometry", &docs), vec![0, 2, 1]);
        assert_eq!(rank("", &docs), vec![0, 1, 2]);
    }
}
