# Safe Markdown for AI Consumption (SMAC)

**Version 1.0 — February 2026**
**Author:** Mihalis Haatainen / Bountyy Oy
**Status:** Proposed standard

## Problem statement

Markdown documentation has two representations: the **rendered** output humans see, and the **raw source** machines process. These representations are not equivalent. Raw markdown contains content that is invisible when rendered — HTML comments, markdown reference links, collapsed sections — but fully readable by any system processing the raw text.

When AI systems process raw markdown, they operate on a superset of what humans reviewed. This breaks the review guarantee: a human approving rendered documentation has not approved the raw source. Any content in the gap between rendered and raw is an unreviewed, AI-only communication channel.

This is not a model alignment failure. It is a preprocessing failure. The fix is architectural.

## Scope

This standard applies to any system that feeds markdown documentation to a language model, including but not limited to:

- IDE copilots (GitHub Copilot, Cursor, Windsurf, etc.)
- Repository AI features ("Ask AI about this repo")
- RAG pipelines indexing documentation
- Internal doc ingestion systems
- Chat interfaces accepting markdown input
- CI/CD systems using AI for code review

## The trust boundary

```
┌─────────────────────────────────────────────────┐
│              RAW MARKDOWN SOURCE                 │
│                                                  │
│  ┌──────────────────────────────────┐            │
│  │     RENDERED CONTENT             │            │
│  │     (what humans review)         │            │
│  │                                  │            │
│  │  Headings, paragraphs, code      │            │
│  │  blocks, tables, images, links   │            │
│  └──────────────────────────────────┘            │
│                                                  │
│  INVISIBLE-WHEN-RENDERED:                        │
│  · HTML comments (<!-- ... -->)                  │
│  · Markdown reference links ([//]: #)            │
│  · Collapsed <details> blocks                    │
│  · Zero-width Unicode characters                 │
│  · HTML entities in comments                     │
│                                                  │
│  ← THIS IS THE AI-ONLY CHANNEL                  │
└─────────────────────────────────────────────────┘
```

**The rendered content is the human trust boundary.** Any system that exposes content outside this boundary to an AI — without explicit disclosure — violates the trust model.

## Requirements

### SMAC-1: Strip HTML comments before LLM ingestion

All HTML comments (`<!-- ... -->`) MUST be removed from markdown before the content is passed to a language model.

**Rationale:** HTML comments are invisible when rendered. They are the primary vector for invisible prompt injection in documentation. Legitimate uses (TODO markers, build directives, lint configs) are developer-tooling concerns and have no relevance to AI-assisted code generation.

**Implementation:**
```python
import re
content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
```

### SMAC-2: Strip markdown reference-only links before LLM ingestion

Markdown reference links that serve no rendered purpose (`[//]: # (...)` and similar patterns used solely for metadata) MUST be removed.

**Rationale:** These are functionally invisible comments — rendered to nothing, but readable in raw source.

**Implementation:**
```python
content = re.sub(r'^\[//\]:\s*#\s*[\("](.*?)[\)"]\s*$', '', content, flags=re.MULTILINE)
```

### SMAC-3: Prefer rendered text over raw source

Where possible, AI systems SHOULD process the rendered (HTML or plaintext) output of markdown rather than raw source. This eliminates the entire class of rendering-gap attacks.

**Rationale:** Rendering markdown first and feeding the result to the LLM collapses the two representations into one. The AI sees what the human sees.

### SMAC-4: Log discarded content

When hidden content is stripped (per SMAC-1, SMAC-2), the system SHOULD log what was removed, including file path, content hash, and timestamp.

**Rationale:** Enables auditing and incident response. If a supply chain attack is discovered, logs show which files contained hidden content.

**Implementation:**
```python
import hashlib, logging

def strip_and_log(content, filepath):
    comments = re.findall(r'<!--.*?-->', content, re.DOTALL)
    for comment in comments:
        logging.info(f"SMAC-1: Stripped HTML comment from {filepath} "
                     f"hash={hashlib.sha256(comment.encode()).hexdigest()[:12]} "
                     f"length={len(comment)}")
    # ... strip and return
```

### SMAC-5: Treat documentation as untrusted input

Documentation MUST be treated as untrusted user input, not as system instructions. Hidden content in documentation MUST NOT be able to override system prompts, tool configurations, or safety boundaries.

**Rationale:** This is the standard security principle of input validation applied to AI systems.

## Compliance levels

| Level | Requirements | Description |
|-------|-------------|-------------|
| **SMAC-L1** | SMAC-1, SMAC-2 | Strip known invisible content |
| **SMAC-L2** | L1 + SMAC-3 | Render-first processing |
| **SMAC-L3** | L2 + SMAC-4, SMAC-5 | Full audit trail and trust boundary |

## Verification

Compliance can be tested using the **Documentation Rendering Parity Test (DRPT)** — a benchmark of 10 README variants with identical rendered content but different hidden elements.

A system passes DRPT if model output is identical (functionally equivalent) across all 10 variants. Any divergence indicates that invisible content is influencing the output.

The DRPT test suite is available at: https://github.com/bountyyfi/invisible-prompt-injection

## The policy question

This standard exists because the answer to one question determines the architecture:

> **Should invisible content be allowed to influence AI-generated code?**

If **yes**: accept the risk that any markdown file can contain an unreviewed AI-only communication channel, and document this in your threat model.

If **no**: implement SMAC-L1 or higher. This is a preprocessing fix, not a model alignment problem.

## FAQ

**Doesn't stripping comments break legitimate developer workflows?**
No. HTML comments in markdown are developer-tooling concerns (TODOs, lint directives, build markers). They have no role in AI-assisted code generation. Stripping them before LLM ingestion does not affect the comments in the source file.

**What about `<details>` blocks?**
Collapsed `<details>` blocks are a gray area — they are technically visible if a user expands them. However, most humans will not expand them during review. SMAC-L2 (render-first) handles this: rendered output includes the expanded content.

**Isn't this just prompt injection?**
The technique is related to prompt injection, but the framing matters. This is not about tricking models — it's about the structural gap between what humans review and what AI processes. The fix is preprocessing, not model hardening.

**Why not fix this in models?**
Models should also be robust to injection. But the preprocessing fix is simpler, more reliable, and eliminates the entire attack class regardless of model capability. Defense in depth means doing both.

## References

- Invisible Prompt Injection research: https://github.com/bountyyfi/invisible-prompt-injection
- DRPT benchmark: included in the above repository
- Bountyy Oy: https://bountyy.fi
- Contact: info@bountyy.fi

## License

This specification is released under CC BY 4.0. You may use, share, and adapt it with attribution.

© 2026 Bountyy Oy
