//! The [`LlmClient`] trait and an OpenAI-compatible implementation for SGLang.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;

/// A minimal chat-completion seam. One method: send a system + user message,
/// get the assistant's text back. Async so the scanner can run many requests
/// concurrently under a semaphore; object-safe so tests inject a mock.
#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn complete(&self, system: &str, user: &str) -> Result<String>;
}

/// OpenAI-compatible client targeting a self-hosted SGLang `/chat/completions`.
///
/// SGLang needs no auth, so the bearer key is a dummy by default. Temperature is
/// pinned to 0 for deterministic triage. A transport error is retried once after
/// a short backoff before giving up.
pub struct OpenAiClient {
    http: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
    /// When true, send `chat_template_kwargs: {"enable_thinking": false}` so
    /// reasoning-capable models (Qwen3.x, GLM, ...) reply with the answer in
    /// `content` instead of leaking chain-of-thought. SGLang exposes no
    /// server-side flag for this on Qwen3.6 — it must be set per request. Plain
    /// OpenAI servers and non-thinking models ignore the extra field, so it is
    /// safe to send unconditionally.
    disable_thinking: bool,
}

impl OpenAiClient {
    pub fn new(
        base_url: &str,
        model: &str,
        api_key: &str,
        timeout: Duration,
        disable_thinking: bool,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key: api_key.to_string(),
            disable_thinking,
        })
    }

    fn endpoint(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }

    async fn post_once(&self, body: &ChatRequest<'_>) -> Result<String> {
        let resp = self
            .http
            .post(self.endpoint())
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .context("sending chat completion request")?;

        let status = resp.status();
        let text = resp.text().await.context("reading response body")?;
        if !status.is_success() {
            anyhow::bail!("endpoint returned {status}: {text}");
        }
        let parsed: ChatResponse =
            serde_json::from_str(&text).context("parsing chat completion response")?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| {
                // Prefer `content`; fall back to `reasoning_content` if a
                // reasoning model/endpoint split its answer there and left
                // `content` empty. The two-pass JSON extractor tolerates the
                // chain-of-thought prefix this may carry.
                let m = c.message;
                if m.content.trim().is_empty() {
                    m.reasoning_content
                } else {
                    m.content
                }
            })
            .unwrap_or_default();
        Ok(content)
    }
}

#[async_trait]
impl LlmClient for OpenAiClient {
    async fn complete(&self, system: &str, user: &str) -> Result<String> {
        let body = ChatRequest {
            model: &self.model,
            temperature: 0.0,
            messages: vec![
                Message {
                    role: "system",
                    content: system,
                },
                Message {
                    role: "user",
                    content: user,
                },
            ],
            chat_template_kwargs: self.disable_thinking.then_some(ChatTemplateKwargs {
                enable_thinking: false,
            }),
        };

        match self.post_once(&body).await {
            Ok(text) => Ok(text),
            Err(first) => {
                tracing::warn!(error = %first, "LLM request failed; retrying once");
                tokio::time::sleep(Duration::from_millis(750)).await;
                self.post_once(&body)
                    .await
                    .with_context(|| format!("LLM request failed twice (first error: {first})"))
            }
        }
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    messages: Vec<Message<'a>>,
    /// Omitted from the JSON entirely when `None`, so plain OpenAI endpoints
    /// never see an unfamiliar field.
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<ChatTemplateKwargs>,
}

#[derive(Serialize)]
struct ChatTemplateKwargs {
    enable_thinking: bool,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    /// `content` may be present-but-null on reasoning models, so accept null as
    /// empty rather than failing to parse.
    #[serde(default, deserialize_with = "null_as_empty")]
    content: String,
    /// Where reasoning models put chain-of-thought; used as a fallback when
    /// `content` is empty. Often null on non-thinking replies.
    #[serde(default, deserialize_with = "null_as_empty")]
    reasoning_content: String,
}

/// Deserialize a possibly-null/absent JSON string field as an empty `String`.
fn null_as_empty<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// A scripted [`LlmClient`] for tests: returns queued responses in order, and
/// records every `(system, user)` prompt it received so tests can assert the
/// context pack was injected. When the queue drains, the last response repeats.
pub struct MockLlmClient {
    responses: Mutex<std::collections::VecDeque<String>>,
    last: Mutex<String>,
    pub seen_prompts: Mutex<Vec<(String, String)>>,
}

impl MockLlmClient {
    /// Build a mock that replies with `responses` in order.
    pub fn new(responses: Vec<String>) -> Self {
        let last = responses.last().cloned().unwrap_or_default();
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            last: Mutex::new(last),
            seen_prompts: Mutex::new(Vec::new()),
        }
    }

    /// The user-message text of every prompt seen so far.
    pub fn seen_user_prompts(&self) -> Vec<String> {
        self.seen_prompts
            .lock()
            .unwrap()
            .iter()
            .map(|(_, u)| u.clone())
            .collect()
    }
}

#[async_trait]
impl LlmClient for MockLlmClient {
    async fn complete(&self, system: &str, user: &str) -> Result<String> {
        self.seen_prompts
            .lock()
            .unwrap()
            .push((system.to_string(), user.to_string()));
        let mut q = self.responses.lock().unwrap();
        Ok(q.pop_front()
            .unwrap_or_else(|| self.last.lock().unwrap().clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(disable_thinking: bool) -> ChatRequest<'static> {
        ChatRequest {
            model: "m",
            temperature: 0.0,
            messages: vec![Message {
                role: "user",
                content: "hi",
            }],
            chat_template_kwargs: disable_thinking.then_some(ChatTemplateKwargs {
                enable_thinking: false,
            }),
        }
    }

    #[test]
    fn request_includes_thinking_kwarg_when_enabled() {
        let json = serde_json::to_string(&body(true)).unwrap();
        assert!(json.contains("chat_template_kwargs"));
        assert!(json.contains("\"enable_thinking\":false"));
    }

    #[test]
    fn request_omits_kwarg_when_disabled_flag_off() {
        // A plain OpenAI endpoint must never see the extra field.
        let json = serde_json::to_string(&body(false)).unwrap();
        assert!(!json.contains("chat_template_kwargs"));
    }

    #[test]
    fn response_falls_back_to_reasoning_content_when_content_empty() {
        let raw = r#"{"choices":[{"message":{"content":"","reasoning_content":"the answer"}}]}"#;
        let parsed: ChatResponse = serde_json::from_str(raw).unwrap();
        let m = parsed.choices.into_iter().next().unwrap().message;
        let picked = if m.content.trim().is_empty() {
            m.reasoning_content
        } else {
            m.content
        };
        assert_eq!(picked, "the answer");
    }

    #[test]
    fn response_prefers_content_and_tolerates_null_reasoning() {
        // The common case: content populated, reasoning_content explicitly null.
        let raw = r#"{"choices":[{"message":{"content":"[]","reasoning_content":null}}]}"#;
        let parsed: ChatResponse = serde_json::from_str(raw).unwrap();
        let m = parsed.choices.into_iter().next().unwrap().message;
        assert_eq!(m.content, "[]");
        assert_eq!(m.reasoning_content, "");
    }
}
