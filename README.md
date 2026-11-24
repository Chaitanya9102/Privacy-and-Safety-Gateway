# Privacy and Safety Gateway

A beginner-friendly Python proof of concept that checks a prompt before it is sent to an AI service. It demonstrates privacy controls and data structures in a compact local web app. It uses only Python's standard library, so there are no packages to install.

## Run the project

1. Open PowerShell in this project folder.
2. Start the local app:

   ```powershell
   python app.py
   ```

   If your computer uses the Python launcher, use `py app.py` instead.

3. Open `http://127.0.0.1:8000` in your browser.
4. Choose **Load example**, then **Analyze prompt**. Inspect the findings and protected preview. The demo detects a suspicious instruction and blocks sending until you select the one-time override.
5. Press **Ctrl+C** in PowerShell to stop the app.

The application binds only to your own computer (`127.0.0.1`). Prompt analysis runs locally. The default local demo service does not call an AI or require an API key.

Use the **Suggestions** button beside the prompt label to insert a sample containing personal data, a credential, or an injection phrase. The **History & audit** panel records each analysis and decision; expand an entry to see its profile, provider, finding positions, categories, protection actions, and override status. The original input is not stored as a separate field. To retain the protected version for later review, enable **Save protected prompt text in local history** in the policy panel and save the policy. This option is off by default; if no matches are found, the protected text can be the same as the input.

The app also attempts to open the browser automatically. If it does not, copy the address printed in PowerShell into a new browser tab. Keep the PowerShell window open while using the page. If port 8000 is busy, run `python app.py --port 8001` and open `http://127.0.0.1:8001`.

## Optional live API

Live mode forwards only the protected prompt to the OpenAI chat completions endpoint. Every prompt still requires a review and explicit send action. Set your key in the same PowerShell window, then run:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
python app.py --live
```

Select **OpenAI API** in the app after it opens. The key is read from the environment and is not saved in the project. Do not paste it into the policy file or source code.

## What the gateway detects

- Email addresses
- Common phone number formats
- Credential assignments such as `password=...` or `api_key=...`
- Payment card numbers that pass the Luhn checksum
- Names and confidential phrases configured in the policy
- A small set of suspicious prompt-injection phrases

The sample name and confidential phrase lists can be edited in the app. Automatic recognition of every name, every credential format, or every injection paraphrase is outside this student prototype.

## Protection and review

Each category can use one of three actions:

- **Mask:** replace each matched character with `*`.
- **Redact:** replace the matched value with a label such as `[REDACTED EMAIL]`.
- **Tokenize:** replace it with a numbered placeholder such as `[CARD_1]`.

After analysis, the app shows the matches and the protected prompt. Suspicious prompt injection is blocked by default. A user can explicitly allow it once after reviewing the preview; the matched instruction remains redacted by policy.

## DSA concepts, explained simply

### Trie (prefix tree)

The `Trie` class stores names and confidential phrases one character at a time. Phrases that share a prefix also share the same first nodes. For example, `internal memo` and `internal roadmap` share the `internal ` part. The scanner follows the prompt's characters through the Trie to find configured phrases without checking every phrase independently at every step.

For a prompt of length `n` and maximum configured phrase length `m`, the simple search here takes at most about `O(n × m)` character checks. It uses extra memory proportional to the total number of characters stored in the phrases.

### Other structures and algorithms

- **Dictionary (`dict`):** maps a finding category, such as `EMAIL`, to its protection action.
- **List:** collects findings from the regular-expression and Trie detectors.
- **Sorting:** orders findings by their position in the prompt.
- **Greedy overlap handling:** gives suspicious-instruction matches priority, then keeps the longest available match and skips overlapping spans before replacing text.
- **Linear scan:** applies replacements from left to right while building the protected prompt.

## Project stages

1. **Detect:** regular expressions find common data formats; the Trie finds configured names and terms.
2. **Protect:** a policy applies masking, redaction, or tokenization.
3. **Review and decide:** the user inspects the preview, can cancel by not sending, or can explicitly override an injection block once.
4. **Audit and measure:** metadata for analyses and sends is recorded, and a small labeled scorecard reports precision, recall, and F1.
5. **Optional API demo:** only after review, the protected prompt can be sent to a configured AI service.

## Detection scorecard

Click **Show sample scorecard** in the app. It compares seven example prompts against expected categories and reports:

- **Precision:** of the categories detected, how many were expected?
- **Recall:** of the expected categories, how many were found?
- **F1:** a combined score based on precision and recall.

The result measures only the small built-in sample; it is not a claim of real-world accuracy.

To print the same sample report in PowerShell, run:

```powershell
python benchmark.py
```

## Privacy audit and saved policy

The app loads default profiles from `data/policy.json` and saves your customized profiles to `data/policy.local.json`; it creates `data/audit.jsonl` when needed. The local policy and audit history are excluded from Git by `.gitignore`. The General, Academic, and Business profiles demonstrate how separate applications can use different rules. History records the time, profile, provider, decision, prompt lengths, finding positions and categories, protection actions, and injection override status. The original input is not stored as a separate field. You can optionally enable **Save protected prompt text in local history** in the policy panel to review the transformed text later; it is off by default and may equal the input if no matches were found. The API service may process the protected prompt when live mode is selected.

## Files

```text
app.py                 Local web server and optional API adapter
privacy_gateway.py     Trie, detectors, policy handling, protection actions
benchmark.py           Labeled examples and precision/recall/F1 calculation
web/index.html         Responsive visual interface
data/policy.json       Editable policy defaults
data/audit.jsonl       Created as privacy decisions occur
```

## Screenshots

These screenshots show the local demo detecting and protecting sample prompts, recording decisions, applying profiles, blocking suspicious instructions, and calculating a sample scorecard. The images use sample data and are framed for consistent display.

<details>
<summary>Dashboard overview</summary>

![Privacy Gateway dashboard](screenshots/01-dashboard-overview.png)

</details>

<details>
<summary>Policy and history overview</summary>

![Policy profiles and audit history](screenshots/02-policy-and-history-overview.png)

</details>

<details>
<summary>Sensitive data detection and protected preview</summary>

![Email, known name, and confidential terms are detected and protected](screenshots/03-sensitive-data-detection.png)

</details>

<details>
<summary>Payment card tokenization and local demo</summary>

![Test payment card replaced by a token before the local demo receives it](screenshots/04-payment-card-tokenization.png)

</details>

<details>
<summary>Policy settings and audit history</summary>

![Configurable protection actions and recent audit records](screenshots/05-policy-and-audit-history.png)

</details>

<details>
<summary>Academic profile protection</summary>

![Academic profile protects sample student information](screenshots/06-academic-profile-protection.png)

</details>

<details>
<summary>Prompt injection detection and blocking</summary>

![Suspicious prompt is detected and blocked pending review](screenshots/07-prompt-injection-blocking.png)

</details>

<details>
<summary>Sample detection scorecard</summary>

![Precision, recall, and F1 score for the built-in sample set](screenshots/08-detection-scorecard.png)

</details>

## Limitations

- Detection uses a small set of regular expressions and phrases. It can miss sensitive information or flag ordinary text.
- Names are found only when entered in the policy; this keeps the example understandable and avoids claiming universal name recognition.
- The Luhn check catches many valid-looking card numbers, but it does not prove that a card is real.
- Tokenization uses placeholders and does not keep a secret map for restoring values.
- This is an educational demonstration, not a production security boundary.
