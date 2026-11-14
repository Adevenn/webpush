# Changelog

## 1.0.0

- Web Push code extracted from Puffin's worker (commit 7f5163f), wire bytes unchanged by default.
- `PushUrgency` (`veryLow`, `low`, `normal`, `high`) on `PushSender.send`; `urgent` still gives `high` or `normal`.
- `PushServices`: closed list of push services, Apple + Mozilla by default.
- Optional `encrypt` parameter on `PushSender` (tests only: fixed salt and sender key).
