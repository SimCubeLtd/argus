//! Token estimation and file chunking.
//!
//! Files that exceed the configured token ceiling are split on line boundaries
//! into chunks, each under the limit. Every chunk records the file line its
//! first line corresponds to (`start_line`, 1-based), so a model that reports
//! "line 5 of the chunk" can be mapped back to the true file line during merge.

/// Estimate token count as `chars / 4` — the cheap heuristic the spec mandates.
pub fn estimate_tokens(text: &str) -> usize {
    text.chars().count() / 4
}

/// A contiguous slice of a file to scan as one unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// 1-based file line of this chunk's first line.
    pub start_line: u32,
    /// The chunk's source text (joined with `\n`, no trailing newline).
    pub text: String,
}

impl Chunk {
    /// Map a model-reported, chunk-relative line (1-based) back to the true file
    /// line. A reported `0`/missing line stays `0`.
    pub fn map_line(&self, chunk_line: u32) -> u32 {
        if chunk_line == 0 {
            0
        } else {
            self.start_line + chunk_line - 1
        }
    }
}

/// Split `text` into chunks each estimated under `max_tokens`. Small files yield
/// a single chunk spanning the whole file. Splitting is on line boundaries so a
/// line is never cut in half. A single line longer than the budget becomes its
/// own (over-budget) chunk rather than being dropped or truncated.
pub fn chunk_file(text: &str, max_tokens: usize) -> Vec<Chunk> {
    let budget = max_tokens.max(1);

    // Whole-file fast path: one chunk starting at line 1.
    if estimate_tokens(text) <= budget {
        return vec![Chunk {
            start_line: 1,
            text: text.to_string(),
        }];
    }

    let lines: Vec<&str> = text.lines().collect();
    let mut chunks = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut current_tokens = 0usize;
    let mut start_line = 1u32; // 1-based line of `current`'s first line.

    for (idx, line) in lines.iter().enumerate() {
        // +1 estimates the newline that rejoins this line to the previous one.
        let line_tokens = estimate_tokens(line) + 1;

        // Flush the accumulated chunk before adding a line that would overflow,
        // but only if we already have content (else a single oversized line
        // would loop forever producing empty chunks).
        if !current.is_empty() && current_tokens + line_tokens > budget {
            chunks.push(Chunk {
                start_line,
                text: current.join("\n"),
            });
            current.clear();
            current_tokens = 0;
            start_line = idx as u32 + 1;
        }

        current.push(line);
        current_tokens += line_tokens;
    }

    if !current.is_empty() {
        chunks.push(Chunk {
            start_line,
            text: current.join("\n"),
        });
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_chars_over_four() {
        assert_eq!(estimate_tokens("abcdefgh"), 2);
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn small_file_is_single_chunk_from_line_one() {
        let chunks = chunk_file("line1\nline2\nline3", 8000);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].text, "line1\nline2\nline3");
    }

    #[test]
    fn oversized_file_splits_under_budget() {
        // 40 lines of ~10 tokens each; a tiny budget forces several chunks.
        let body: String = (1..=40)
            .map(|i| format!("const x{i} = someValueHere{i};"))
            .collect::<Vec<_>>()
            .join("\n");
        let chunks = chunk_file(&body, 20);
        assert!(chunks.len() > 1, "expected multiple chunks");
        for c in &chunks {
            assert!(
                estimate_tokens(&c.text) <= 20 || c.text.lines().count() == 1,
                "chunk over budget: {} tokens",
                estimate_tokens(&c.text)
            );
        }
    }

    #[test]
    fn chunk_start_lines_are_contiguous_and_map_back() {
        let body: String = (1..=30)
            .map(|i| format!("statement number {i} goes here"))
            .collect::<Vec<_>>()
            .join("\n");
        let chunks = chunk_file(&body, 15);

        // The first line of chunk N maps to its own start_line.
        for c in &chunks {
            assert_eq!(c.map_line(1), c.start_line);
        }
        // Reassembling chunk texts reproduces every original line in order.
        let reassembled: Vec<String> = chunks
            .iter()
            .flat_map(|c| c.text.lines().map(String::from))
            .collect();
        assert_eq!(
            reassembled,
            body.lines().map(String::from).collect::<Vec<_>>()
        );
    }

    #[test]
    fn line_far_into_a_later_chunk_maps_correctly() {
        // start_line 11, chunk-relative line 3 -> file line 13.
        let c = Chunk {
            start_line: 11,
            text: "a\nb\nc\nd".into(),
        };
        assert_eq!(c.map_line(3), 13);
        assert_eq!(c.map_line(0), 0);
    }

    #[test]
    fn single_oversized_line_becomes_its_own_chunk() {
        let huge = "x".repeat(1000);
        let chunks = chunk_file(&huge, 10);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_line, 1);
    }
}
