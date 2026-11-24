# Project report: Privacy and Safety Gateway

## Problem

People may accidentally include personal, financial, or confidential details in prompts sent to generative AI services. Prompt-injection text can also try to change how a connected AI system behaves. This project adds a small inspection and protection step before sending a prompt.

## Proposed solution

The gateway scans a prompt locally, shows detected items, applies a configurable action, and displays the resulting text for review. The user can send the protected text to a local demo service or, when deliberately enabled, an AI API. Suspicious instructions are blocked by default and require a one-time user override to continue.

## DSA used

The central DSA feature is a **Trie**, also called a prefix tree. It stores user-configured names and confidential terms. The scanner follows characters from each prompt position through Trie nodes and reports a match when it reaches a stored phrase. Lists hold findings, dictionaries hold policy actions, and sorting by character position helps the gateway safely replace matches without moving offsets.

## Protection policy

The user can choose a General, Academic, or Business policy profile and configure names, confidential terms, and one action per category. Masking keeps the original text length, redaction replaces it with a clear label, and tokenization substitutes a numbered placeholder. Overlapping detections prioritize injection phrases, then prefer the longest available match.

## Safety and audit

The app flags a selected list of prompt-injection phrases. A flagged prompt is blocked by default. The interface makes the protected version visible before any send action and records a one-time override when the user elects to proceed. Expandable history records decision metadata, finding positions, categories, applied actions, provider, and the active profile. The original input is not stored as a separate field; saving the protected prompt text is an optional policy setting and is off by default. If no matches were found, the protected text may equal the input.

## Evaluation

Seven labeled sample prompts cover email, phone, credentials, a card number, a configured confidential phrase, prompt injection, and an ordinary prompt. Precision, recall, and F1 are calculated by comparing detected categories with expected categories. This small sample demonstrates measurement; it does not establish real-world accuracy.

## Limitations and future work

The prototype cannot detect every name, credential, sensitive identifier, or paraphrased injection. Future work could add a larger labeled dataset, more configurable detector rules, user-specific policies, and additional AI provider adapters. Those extensions should preserve the review step and minimize sensitive information stored in audit logs.
