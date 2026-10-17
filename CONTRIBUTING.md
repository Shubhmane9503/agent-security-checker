# Contributing

Thanks for your interest. Contributions to this project are **by invitation only**.

## How to get access

1. Open an issue using the **Request contributor access** template (name, GitHub handle, what you want to contribute).
2. Wait for the maintainer to approve it in the issue.
3. Only after approval, open a pull request and put the approval issue number in the PR template.

Pull requests from people who have not been approved may be closed without review. Small questions and bug reports do not need approval: use the Bug report template.

## Run the tests

Node 18+ and no dependencies are needed.

```bash
npm test                 # runs tests/run.mjs and tests/v2.mjs
npm run build            # regenerates lib/samples.js, docs/RULES.md and standalone.html
```

Run `npm run build` after editing source files, and commit the regenerated files. All tests must pass before you open a PR.

## Add a rule

1. Add an entry to `CATALOG` in `lib/meta.js` with a unique **rule id** (category prefix plus number, such as `PI-8`), a title, a **severity** (critical, high, medium or low), OWASP/ATLAS tags, why it matters, a weak and a better example, a fix and an effort level.
2. Implement the check in `engine.js`. Keep every regex bounded and linear-time. No network calls, no `eval`.
3. Add tests in `tests/v2.mjs`: at least one config that triggers the rule, one that must not (including a hardened one), and a case for unusual wording.
4. Run `npm run build` and `npm test`, then update the rule count in the README if it changed.

## Security reporting

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Conduct

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
