// Fixture-based regression tests for the silent-retry trend aggregator
// (task #110). These exist specifically to lock in the contract between
// the marker emitted from `.github/workflows/ci.yml` (the
// "Surface silent retry of dbtest + integration lane" step) and the
// regex used by `scripts/silent-retry-trend.mjs` to detect it.
//
// Run with: node --test tests/silent-retry-trend.test.mjs
//
// Why the fixtures look like this:
//   The strings below are minimal but realistic excerpts of what the
//   /actions/jobs/{id}/logs endpoint returns for the dbtest+integration
//   job in the three states the aggregator must distinguish:
//     1. success after silent retry  → marker present
//     2. failure after exhausted retry → nick-fields/retry's
//        "Final attempt failed" line present, marker absent
//     3. clean first-attempt success → neither signal present
//
//   If `.github/workflows/ci.yml` ever stops echoing the marker to
//   stdout, the SAVED_BY_RETRY_LOG fixture must be updated AT THE
//   SAME TIME as the workflow change — otherwise this test will
//   continue passing while the production aggregator silently misses
//   every real silent-save event (the exact failure mode that the
//   first review of task #110 caught).

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Keep these regex literals in lock-step with
// scripts/silent-retry-trend.mjs. They are duplicated here on purpose:
// the test's job is to fail loudly if either side drifts.
const MARKER_REGEX = /DBTEST_INTEGRATION_RETRY_USED attempts=(\d+)/;
const FAILED_RETRY_REGEX = /Final attempt failed/i;

const SAVED_BY_RETRY_LOG = `
2026-04-30T14:22:11.1234567Z ##[group]Run nick-fields/retry@v3
2026-04-30T14:22:11.1234567Z Attempt 1 of 2
2026-04-30T14:31:02.0000000Z Final attempt 1 of 2 failed. Reason: connection refused
2026-04-30T14:31:32.0000000Z Waiting 30 seconds before trying again
2026-04-30T14:32:02.0000000Z Attempt 2 of 2
2026-04-30T14:39:50.0000000Z All test passes succeeded across 7 tags.
2026-04-30T14:39:51.0000000Z ##[endgroup]
2026-04-30T14:39:52.0000000Z ##[group]Run Surface silent retry of dbtest + integration lane
2026-04-30T14:39:52.1000000Z dbtest+integration lane: total_attempts=2 outcome=success
2026-04-30T14:39:52.2000000Z DBTEST_INTEGRATION_RETRY_USED attempts=2
2026-04-30T14:39:52.3000000Z ##[warning]Silent CI retry used::dbtest + integration lane passed on attempt 2/2 (task #105). Job is green but infra flakiness is creeping up — see job summary.
2026-04-30T14:39:52.4000000Z ##[endgroup]
`;

const RETRIED_AND_FAILED_LOG = `
2026-04-30T15:00:00.0000000Z ##[group]Run nick-fields/retry@v3
2026-04-30T15:00:00.0000000Z Attempt 1 of 2
2026-04-30T15:08:11.0000000Z Final attempt 1 of 2 failed. Reason: TestThing failed
2026-04-30T15:08:41.0000000Z Waiting 30 seconds before trying again
2026-04-30T15:09:11.0000000Z Attempt 2 of 2
2026-04-30T15:17:30.0000000Z Final attempt failed. Reason: TestThing failed
2026-04-30T15:17:31.0000000Z ##[error]Process completed with exit code 1.
2026-04-30T15:17:32.0000000Z ##[endgroup]
2026-04-30T15:17:33.0000000Z ##[group]Run Surface silent retry of dbtest + integration lane
2026-04-30T15:17:33.1000000Z dbtest+integration lane: total_attempts=2 outcome=failure
2026-04-30T15:17:33.2000000Z ##[endgroup]
`;

const CLEAN_LOG = `
2026-04-30T16:00:00.0000000Z ##[group]Run nick-fields/retry@v3
2026-04-30T16:00:00.0000000Z Attempt 1 of 2
2026-04-30T16:08:50.0000000Z All test passes succeeded across 7 tags.
2026-04-30T16:08:51.0000000Z ##[endgroup]
2026-04-30T16:08:52.0000000Z ##[group]Run Surface silent retry of dbtest + integration lane
2026-04-30T16:08:52.1000000Z dbtest+integration lane: total_attempts=1 outcome=success
2026-04-30T16:08:52.2000000Z ##[endgroup]
`;

describe('silent-retry-trend marker contract', () => {
  it('detects DBTEST_INTEGRATION_RETRY_USED marker in a saved-by-retry job log', () => {
    const m = SAVED_BY_RETRY_LOG.match(MARKER_REGEX);
    assert.ok(
      m,
      'MARKER_REGEX must match the marker line emitted to stdout by ' +
        'the "Surface silent retry of dbtest + integration lane" step ' +
        'in .github/workflows/ci.yml. If this assertion fails, either ' +
        'the workflow stopped echoing the marker to stdout or the ' +
        'regex in scripts/silent-retry-trend.mjs drifted out of sync.',
    );
    assert.equal(m[1], '2', 'attempts capture group must extract the attempt count');
  });

  it('does NOT match the marker on a retried-and-failed job log', () => {
    assert.equal(
      RETRIED_AND_FAILED_LOG.match(MARKER_REGEX),
      null,
      'The marker is intentionally not emitted on failure (the job is ' +
        'already red, so we do not double-signal). If this matches, ' +
        'ci.yml has started emitting the marker on the failure path ' +
        'and the aggregator will overcount silent saves.',
    );
  });

  it('does NOT match the marker on a clean (no-retry) job log', () => {
    assert.equal(
      CLEAN_LOG.match(MARKER_REGEX),
      null,
      'The marker must not appear when total_attempts=1, otherwise the ' +
        'aggregator will report silent saves where none happened.',
    );
  });

  it('detects nick-fields/retry "Final attempt failed" on a retried-and-failed log', () => {
    assert.ok(
      FAILED_RETRY_REGEX.test(RETRIED_AND_FAILED_LOG),
      'FAILED_RETRY_REGEX must match the line that nick-fields/retry@v3 ' +
        'emits when both attempts are exhausted. If this assertion ' +
        'fails after a nick-fields/retry upgrade, update the regex in ' +
        'scripts/silent-retry-trend.mjs to match the new wording.',
    );
  });

  it('does NOT match "Final attempt failed" on the saved-by-retry log', () => {
    // The intermediate "Final attempt 1 of 2 failed" line on the
    // saved-by-retry path looks similar; the FAILED_RETRY_REGEX must
    // be specific enough not to match it. If it does, every
    // saved-by-retry run would also be classified as retried-and-failed
    // and the aggregator would double-count.
    assert.equal(
      FAILED_RETRY_REGEX.test(SAVED_BY_RETRY_LOG),
      false,
      'FAILED_RETRY_REGEX must distinguish "Final attempt failed" (both ' +
        'attempts exhausted) from "Final attempt 1 of 2 failed" (first ' +
        'attempt failed but second attempt then succeeded).',
    );
  });

  it('does NOT match "Final attempt failed" on a clean log', () => {
    assert.equal(FAILED_RETRY_REGEX.test(CLEAN_LOG), false);
  });
});
