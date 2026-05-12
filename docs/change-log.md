# Obsidian Change Log

## 2026-05-12 — Documentation and Portfolio Framing Refresh

### 1) Educational framing updates
- Reworked README opening and project summary to clearly frame Obsidian as an educational/local scanner.
- Added explicit non-replacement disclaimer for professional security testing.
- Standardized language around portfolio use and removed inflated product positioning.

### 2) Feature-claim alignment with implemented code
- Updated documentation language to match actual scanner behavior:
  - Rule-registry scanner with profile modes (`quick`, `standard`, `deep`)
  - Pattern-based checks for injection, auth/access, config/header issues, and secret exposure
  - JSON output and CLI severity gate (`--fail-on`)
- Avoided claiming exhaustive coverage or professional-grade guarantees.

### 3) Portfolio/UI preview improvements
- Refined `docs/preview/index.html` with terminal-style black/green visual design.
- Added clear pipeline diagram: Input → Parse → Detect → Report.
- Added implemented scan category cards, educational disclaimer, tech stack badges, and repo link.
- Ensured responsive layout and no external image dependencies.

### 4) Recruiter/dev experience improvements
- Expanded quick-start commands in README for dependency install and sample scans.
- Added concise demo workflow for CLI and output modes recruiters can run quickly.
- Updated screenshot documentation to use “Portfolio Preview/UI Preview” framing.
