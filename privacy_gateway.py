"""Core privacy checks for the beginner Privacy and Safety Gateway project."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any


DEFAULT_POLICY: dict[str, Any] = {
    "sensitive_terms": ["Project Falcon", "internal roadmap", "do not share"],
    "known_names": ["Alex Morgan"],
    "actions": {
        "EMAIL": "MASK",
        "PHONE": "MASK",
        "CREDENTIAL": "REDACT",
        "CARD": "TOKENIZE",
        "NAME": "MASK",
        "CONFIDENTIAL": "REDACT",
        "PROMPT_INJECTION": "REDACT",
    },
    "block_prompt_injection": True,
    "store_protected_prompts": False,
}

CATEGORIES = list(DEFAULT_POLICY["actions"])
VALID_ACTIONS = {"MASK", "REDACT", "TOKENIZE"}


class TrieNode:
    """One Trie node: its children are the next character choices."""

    def __init__(self) -> None:
        self.children: dict[str, TrieNode] = {}
        self.category: str | None = None


class Trie:
    """A beginner-friendly prefix tree for matching configured phrases."""

    def __init__(self) -> None:
        self.root = TrieNode()

    def insert(self, phrase: str, category: str) -> None:
        node = self.root
        for character in phrase.casefold():
            if character not in node.children:
                node.children[character] = TrieNode()
            node = node.children[character]
        node.category = category

    def find_all(self, text: str) -> list[tuple[int, int, str]]:
        """Return (start, end, category) matches, with end excluded."""
        source = text.casefold()
        found: list[tuple[int, int, str]] = []
        for start in range(len(source)):
            node = self.root
            for end in range(start, len(source)):
                character = source[end]
                if character not in node.children:
                    break
                node = node.children[character]
                if node.category:
                    # Require word boundaries, so "Ann" doesn't match "annual".
                    left_ok = start == 0 or not source[start - 1].isalnum()
                    right_ok = end + 1 == len(source) or not source[end + 1].isalnum()
                    if left_ok and right_ok:
                        found.append((start, end + 1, node.category))
        return found


@dataclass
class Finding:
    category: str
    action: str
    start: int
    end: int
    value: str
    suspicious: bool = False

    def public_data(self) -> dict[str, Any]:
        return asdict(self)


def normalize_policy(raw: dict[str, Any] | None) -> dict[str, Any]:
    """Fill defaults and reject malformed values before using a policy."""
    raw = raw or {}
    raw_actions = raw.get("actions", {})
    if not isinstance(raw_actions, dict):
        raw_actions = {}
    policy = {
        "sensitive_terms": raw.get("sensitive_terms", DEFAULT_POLICY["sensitive_terms"]),
        "known_names": raw.get("known_names", DEFAULT_POLICY["known_names"]),
        "actions": {**DEFAULT_POLICY["actions"], **raw_actions},
        "block_prompt_injection": raw.get("block_prompt_injection", True),
        "store_protected_prompts": raw.get("store_protected_prompts", False),
    }
    for key in ("sensitive_terms", "known_names"):
        values = policy[key]
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            policy[key] = list(DEFAULT_POLICY[key])
        else:
            policy[key] = [item.strip() for item in values if item.strip()][:100]
    clean_actions = dict(DEFAULT_POLICY["actions"])
    if isinstance(policy["actions"], dict):
        for category, action in policy["actions"].items():
            category = str(category).upper()
            action = str(action).upper()
            if category in CATEGORIES and action in VALID_ACTIONS:
                clean_actions[category] = action
    policy["actions"] = clean_actions
    policy["block_prompt_injection"] = bool(policy["block_prompt_injection"])
    policy["store_protected_prompts"] = bool(policy["store_protected_prompts"])
    return policy


def luhn_is_valid(digits: str) -> bool:
    """Check the simple checksum commonly used by payment card numbers."""
    total = 0
    double_next = False
    for character in reversed(digits):
        number = int(character)
        if double_next:
            number *= 2
            if number > 9:
                number -= 9
        total += number
        double_next = not double_next
    return len(digits) in range(13, 20) and total % 10 == 0


def scan_prompt(prompt: str, raw_policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Find sensitive data and return a protected version of the prompt."""
    policy = normalize_policy(raw_policy)
    candidates: list[Finding] = []

    patterns = [
        ("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
        ("PHONE", re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\w)")),
        ("CREDENTIAL", re.compile(r"\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;]+", re.I)),
        ("CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ]
    for category, pattern in patterns:
        for match in pattern.finditer(prompt):
            if category == "CARD" and not luhn_is_valid(re.sub(r"\D", "", match.group())):
                continue
            candidates.append(Finding(category, policy["actions"][category], match.start(), match.end(), match.group()))

    trie = Trie()
    for name in policy["known_names"]:
        trie.insert(name, "NAME")
    for term in policy["sensitive_terms"]:
        trie.insert(term, "CONFIDENTIAL")
    for start, end, category in trie.find_all(prompt):
        candidates.append(Finding(category, policy["actions"][category], start, end, prompt[start:end]))

    injection_phrases = [
        "ignore all previous instructions", "ignore previous instructions",
        "disregard all prior instructions", "reveal the system prompt",
        "show me your hidden instructions", "bypass safety rules",
        "developer message", "exfiltrate the data", "act as an unrestricted",
    ]
    lowered = prompt.casefold()
    for phrase in injection_phrases:
        start = lowered.find(phrase)
        while start != -1:
            candidates.append(Finding("PROMPT_INJECTION", policy["actions"]["PROMPT_INJECTION"],
                                      start, start + len(phrase), prompt[start:start + len(phrase)], True))
            start = lowered.find(phrase, start + len(phrase))

    # Prefer redacting suspicious instructions if they overlap another match;
    # otherwise keep the longest match at the earliest available position.
    candidates.sort(key=lambda item: (not item.suspicious, item.start,
                                      -(item.end - item.start), item.category))
    selected: list[Finding] = []
    for finding in candidates:
        overlaps = any(finding.start < chosen.end and chosen.start < finding.end for chosen in selected)
        if overlaps:
            continue
        selected.append(finding)
    selected.sort(key=lambda item: (item.start, item.end))

    pieces: list[str] = []
    cursor = 0
    token_counts: dict[str, int] = {}
    for finding in selected:
        pieces.append(prompt[cursor:finding.start])
        if finding.action == "MASK":
            replacement = "*" * max(1, finding.end - finding.start)
        elif finding.action == "TOKENIZE":
            token_counts[finding.category] = token_counts.get(finding.category, 0) + 1
            replacement = f"[{finding.category}_{token_counts[finding.category]}]"
        else:
            replacement = f"[REDACTED {finding.category}]"
        pieces.append(replacement)
        cursor = finding.end
    pieces.append(prompt[cursor:])
    protected_prompt = "".join(pieces)

    return {
        "protected_prompt": protected_prompt,
        "findings": [finding.public_data() for finding in selected],
        "injection_detected": any(finding.suspicious for finding in candidates),
        "blocked_by_policy": policy["block_prompt_injection"] and any(f.suspicious for f in candidates),
        "original_length": len(prompt),
        "protected_length": len(protected_prompt),
    }
