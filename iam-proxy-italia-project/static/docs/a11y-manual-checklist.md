# Accessibility Manual Checklist

This checklist captures manual evidence that complements automated CI checks.

## Screen reader checks

- [ ] Validate key user flows with NVDA/JAWS or VoiceOver.
- [ ] Verify heading hierarchy, control names, and state announcements.
- [ ] Confirm dynamic content updates are announced appropriately.

## Keyboard and interaction checks

- [ ] Confirm logical tab order and visible focus indicators.
- [ ] Confirm no keyboard traps are present.
- [ ] Validate Enter/Space/Escape behavior for interactive controls.

## Zoom and reflow checks

- [ ] Test browser zoom up to 400% on desktop layouts.
- [ ] Verify no clipped content, overlap, or hidden functionality.
- [ ] Verify no unintended horizontal scrolling at supported breakpoints.

## Governance

- [ ] Record reviewer, date, and tested pages in release notes.
- [ ] Open follow-up issues for non-blocking best-practice findings.
