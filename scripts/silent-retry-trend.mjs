#!/usr/bin/env node
// DNS Tool — Silent CI Retry Trend Aggregator (task #110)
//
// What this does:
//   Walks the last N days of `ci.yml` runs via the GitHub Actions API,
//   inspects the `Handler Tests — dbtest + integration` job on each
//   run, and counts how often the lane was either:
//     (a) "saved by retry"     — passed only because nick-fields/retry@v3
//                                ran the inner step a second time
//                                (detected via the stable
//                                `DBTEST_INTEGRATION_RETRY_USED`
//                                marker emitted by task #105's
//                                "Surface silent retry of dbtest +
//                                integration lane" step), OR
//     (b) "retried & failed"   — retry was attempted but both attempts
//                                failed, so the job is already red and
//                                does NOT need a silent-save signal.
//
//   The aggregate trend is then posted to a single tracking issue so
//   maintainers can see at a glance whether the silent-save rate is
//   creeping up BEFORE both attempts start failing in earnest.
//
// Why this exists:
//   Task #105 made per-run silent retries observable. This script
//   answers the per-month question "how often did the dbtest lane get
//   saved by retry this month?" without anyone having to manually scan
//   recent runs.
//
// Stable contract with task #105:
//   The marker prefix "DBTEST_INTEGRATION_RETRY_USED" must NOT change
//   in `.github/workflows/ci.yml` without also updating MARKER_REGEX
//   below. The marker is intentionally written into the job log (via
//   the `echo` of the marker line and via the comment-preserved tag in
//   $GITHUB_STEP_SUMMARY) so it is grep-able from the raw job log
//   endpoint without needing to download archived run summaries.
//
// Stable contract with nick-fields/retry@v3:
//   When BOTH attempts of the wrapped command fail, the action emits
//   the literal text "Final attempt failed" in the job log just before
//   it propagates the failure. We use that as the "retried & failed"
//   signal. If a future upgrade of nick-fields/retry changes the
//   wording, FAILED_RETRY_REGEX below must be updated.
//
// Inputs (env):
//   GITHUB_TOKEN       Required. Needs `actions:read` to list runs/jobs
//                      and read job logs, and `issues:write` to post
//                      the trend.
//   GITHUB_REPOSITORY  Required when running in CI ("owner/repo").
//                      Falls back to "IT-Help-San-Diego/dns-tool-intel"
//                      so the script is runnable locally for ad-hoc
//                      checks.
//   DAYS_LOOKBACK      Optional. Default: 35 (≈ one calendar month +
//                      a week of overlap so the most recent month is
//                      not under-counted at month-boundary scrapes).
//   TARGET_WORKFLOW    Optional. Default: "ci.yml". The workflow file
//                      whose runs we walk.
//   TARGET_JOB_NAME    Optional. Default: "Handler Tests — dbtest +
//                      integration". Must exactly match the `name:` of
//                      the job in ci.yml that wraps the retry step.
//   TRACKING_ISSUE_TITLE
//                      Optional. Default: "CI Silent Retry Trend —
//                      handler-tests-db-integration". Used to find or
//                      create the persistence target issue.
//   DRY_RUN            Optional. If "1", prints the report to stdout
//                      and skips the GitHub issue write. Useful for
//                      local iteration.

import { Octokit } from '@octokit/rest';

const MARKER_REGEX = /DBTEST_INTEGRATION_RETRY_USED attempts=(\d+)/;
// nick-fields/retry@v3 prints this exact phrase right before bubbling
// up the final failure. See the contract note in the file header.
const FAILED_RETRY_REGEX = /Final attempt failed/i;

const DAYS_LOOKBACK = Number.parseInt(process.env.DAYS_LOOKBACK || '35', 10);
const TARGET_WORKFLOW = process.env.TARGET_WORKFLOW || 'ci.yml';
const TARGET_JOB_NAME =
  process.env.TARGET_JOB_NAME || 'Handler Tests — dbtest + integration';
const TRACKING_ISSUE_TITLE =
  process.env.TRACKING_ISSUE_TITLE ||
  'CI Silent Retry Trend — handler-tests-db-integration';
const DRY_RUN = process.env.DRY_RUN === '1';

function parseRepo() {
  const slug =
    process.env.GITHUB_REPOSITORY || 'IT-Help-San-Diego/dns-tool-intel';
  const [owner, repo] = slug.split('/');
  if (!owner || !repo) {
    throw new Error(`GITHUB_REPOSITORY must be "owner/repo", got "${slug}"`);
  }
  return { owner, repo };
}

function ymKey(dateIso) {
  // Bucket by calendar month in UTC. Using UTC keeps the bucket stable
  // regardless of which runner timezone the script happens to run on.
  const d = new Date(dateIso);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

function newBucket() {
  return {
    total_runs: 0,
    saved_by_retry: 0,
    retried_and_failed: 0,
    clean: 0,
    skipped: 0,
  };
}

async function listRecentRuns(octokit, owner, repo, sinceIso) {
  // The Actions API does not expose a server-side `created>=` filter
  // for workflow runs, so we paginate newest-first and stop as soon as
  // we cross the lookback boundary. This keeps us inside the 1000-run
  // pagination cap on busy repos and bounds the API spend per
  // scheduled invocation.
  const sinceMs = new Date(sinceIso).getTime();
  const runs = [];
  for await (const page of octokit.paginate.iterator(
    octokit.actions.listWorkflowRuns,
    {
      owner,
      repo,
      workflow_id: TARGET_WORKFLOW,
      per_page: 100,
      // We deliberately include both push and pull_request runs so the
      // aggregate reflects all triggered traffic on the lane, not just
      // merged runs. Filter out re-runs of the same attempt so each
      // logical run is counted once.
    },
  )) {
    let crossedBoundary = false;
    for (const run of page.data) {
      if (new Date(run.created_at).getTime() < sinceMs) {
        crossedBoundary = true;
        break;
      }
      // run_attempt > 1 means a maintainer manually re-ran the workflow
      // — that's a separate signal from the in-step retry we're
      // counting and would double-count the same logical CI run.
      if ((run.run_attempt || 1) > 1) continue;
      runs.push(run);
    }
    if (crossedBoundary) break;
  }
  return runs;
}

async function classifyRun(octokit, owner, repo, run) {
  const jobs = await octokit.paginate(octokit.actions.listJobsForWorkflowRun, {
    owner,
    repo,
    run_id: run.id,
    per_page: 100,
    filter: 'latest',
  });
  const job = jobs.find((j) => j.name === TARGET_JOB_NAME);
  if (!job) {
    // Most likely a run from before the lane existed, or a workflow
    // file edit removed the job temporarily. Don't let either inflate
    // the denominator.
    return { classification: 'skipped', reason: 'job_not_found' };
  }
  // In-progress jobs have no log we can grep yet — skip them rather
  // than guessing at the outcome.
  if (job.status !== 'completed') {
    return { classification: 'skipped', reason: 'in_progress' };
  }

  let logText = '';
  try {
    // The redirect-followed body of this endpoint is the plain-text job
    // log. Octokit returns it as the response data.
    const res = await octokit.actions.downloadJobLogsForWorkflowRun({
      owner,
      repo,
      job_id: job.id,
    });
    logText = typeof res.data === 'string' ? res.data : String(res.data ?? '');
  } catch (err) {
    // Logs older than ~90 days get garbage-collected by GitHub. That's
    // fine — we just can't classify this run, so it's "skipped" rather
    // than miscounted as clean.
    if (err.status === 410 || err.status === 404) {
      return { classification: 'skipped', reason: `log_gone_${err.status}` };
    }
    throw err;
  }

  const markerMatch = logText.match(MARKER_REGEX);
  if (markerMatch) {
    return {
      classification: 'saved_by_retry',
      attempts: Number.parseInt(markerMatch[1], 10),
      job_url: job.html_url,
    };
  }

  if (job.conclusion === 'failure' && FAILED_RETRY_REGEX.test(logText)) {
    return {
      classification: 'retried_and_failed',
      job_url: job.html_url,
    };
  }

  // Job ended (success or otherwise) without the silent-save marker
  // and without nick-fields/retry's final-attempt-failed line. Either
  // attempt 1 passed cleanly or the failure happened outside the
  // wrapped retry step. Either way it is not a silent-retry signal.
  return { classification: 'clean', job_url: job.html_url };
}

function renderReport(buckets, sinceIso, untilIso, owner, repo) {
  const months = Object.keys(buckets).sort().reverse();
  const lines = [];
  lines.push(
    `# CI silent-retry trend — \`${TARGET_JOB_NAME}\``,
  );
  lines.push('');
  lines.push(
    `Auto-generated by \`scripts/silent-retry-trend.mjs\` (task #110). ` +
      `Window: \`${sinceIso}\` → \`${untilIso}\` ` +
      `(${DAYS_LOOKBACK} days). Source: \`${owner}/${repo}\` workflow ` +
      `\`${TARGET_WORKFLOW}\`.`,
  );
  lines.push('');
  lines.push(
    'The "saved by retry" column is the **silent-save** signal we ' +
      'instrumented in task #105 — runs where the lane was green only ' +
      'because `nick-fields/retry@v3` ran the inner step a second ' +
      'time. A creeping value here is the leading indicator that the ' +
      'underlying infra (mirror.gcr.io pulls, Postgres service ' +
      'startup, runner CPU contention) is degrading. A sustained ' +
      'increase means investigate **before** both attempts start ' +
      'failing in earnest.',
  );
  lines.push('');
  lines.push(
    'The "retried & failed" column is included for context only — ' +
      'those runs are already red, the job UI already surfaces them, ' +
      'and they do not need a silent-save annotation.',
  );
  lines.push('');
  lines.push(
    '| Month (UTC) | Total runs | Saved by retry | Save rate | Retried & failed | Clean | Skipped |',
  );
  lines.push(
    '|-------------|-----------:|---------------:|----------:|-----------------:|------:|--------:|',
  );
  for (const ym of months) {
    const b = buckets[ym];
    const denom = b.total_runs - b.skipped;
    const rate =
      denom > 0
        ? `${((b.saved_by_retry / denom) * 100).toFixed(1)}%`
        : 'n/a';
    lines.push(
      `| ${ym} | ${b.total_runs} | ${b.saved_by_retry} | ${rate} | ${b.retried_and_failed} | ${b.clean} | ${b.skipped} |`,
    );
  }
  if (months.length === 0) {
    lines.push('| _(no runs in window)_ |  |  |  |  |  |  |');
  }
  lines.push('');
  lines.push(
    `Generated at \`${new Date().toISOString()}\`. Re-run via the ` +
      '`CI Silent Retry Trend` workflow (`workflow_dispatch`) to refresh.',
  );
  return lines.join('\n');
}

async function findOrCreateTrackingIssue(octokit, owner, repo) {
  // Search both open and closed so a previously-closed tracking issue
  // is reused rather than spawning a new one each time someone tidies
  // the issue tracker.
  for (const state of ['open', 'closed']) {
    for await (const page of octokit.paginate.iterator(
      octokit.issues.listForRepo,
      { owner, repo, state, per_page: 100, creator: undefined },
    )) {
      for (const issue of page.data) {
        if (issue.pull_request) continue;
        if (issue.title === TRACKING_ISSUE_TITLE) {
          return issue;
        }
      }
    }
  }
  const created = await octokit.issues.create({
    owner,
    repo,
    title: TRACKING_ISSUE_TITLE,
    body:
      'Tracking issue for the monthly silent-retry trend on the ' +
      '`handler-tests-db-integration` lane.\n\n' +
      'This issue is updated automatically by ' +
      '`scripts/silent-retry-trend.mjs` (task #110). The most recent ' +
      'snapshot lives in the issue body; each scheduled run also adds ' +
      'a dated comment so the historical trend is preserved.',
    labels: ['type:enhancement'],
  });
  return created.data;
}

async function persistReport(octokit, owner, repo, report) {
  const issue = await findOrCreateTrackingIssue(octokit, owner, repo);
  await octokit.issues.update({
    owner,
    repo,
    issue_number: issue.number,
    body: report,
    state: 'open',
  });
  await octokit.issues.createComment({
    owner,
    repo,
    issue_number: issue.number,
    body: `Snapshot @ ${new Date().toISOString()}\n\n${report}`,
  });
  return issue;
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error('GITHUB_TOKEN is required');
  }
  const { owner, repo } = parseRepo();
  const octokit = new Octokit({ auth: token });

  const untilIso = new Date().toISOString();
  const sinceIso = new Date(
    Date.now() - DAYS_LOOKBACK * 24 * 60 * 60 * 1000,
  ).toISOString();

  console.log(
    `[silent-retry-trend] window ${sinceIso} → ${untilIso} (${DAYS_LOOKBACK}d)`,
  );
  console.log(`[silent-retry-trend] repo ${owner}/${repo} workflow ${TARGET_WORKFLOW}`);

  const runs = await listRecentRuns(octokit, owner, repo, sinceIso);
  console.log(`[silent-retry-trend] inspecting ${runs.length} runs`);

  const buckets = {};
  for (const run of runs) {
    const ym = ymKey(run.created_at);
    if (!buckets[ym]) buckets[ym] = newBucket();
    buckets[ym].total_runs++;

    let result;
    try {
      result = await classifyRun(octokit, owner, repo, run);
    } catch (err) {
      console.warn(
        `[silent-retry-trend] run ${run.id} (${run.html_url}) failed to classify: ${err.message}`,
      );
      result = { classification: 'skipped', reason: 'classify_error' };
    }
    buckets[ym][result.classification]++;
    if (result.classification === 'saved_by_retry') {
      console.log(
        `[silent-retry-trend]   saved-by-retry attempts=${result.attempts} ${result.job_url}`,
      );
    } else if (result.classification === 'retried_and_failed') {
      console.log(
        `[silent-retry-trend]   retried-and-failed ${result.job_url}`,
      );
    }
  }

  const report = renderReport(buckets, sinceIso, untilIso, owner, repo);
  console.log('\n----- REPORT -----\n');
  console.log(report);
  console.log('\n----- /REPORT -----\n');

  if (DRY_RUN) {
    console.log('[silent-retry-trend] DRY_RUN=1 set, skipping issue write');
    return;
  }

  const issue = await persistReport(octokit, owner, repo, report);
  console.log(
    `[silent-retry-trend] posted to issue #${issue.number} (${issue.html_url})`,
  );
}

main().catch((err) => {
  console.error('[silent-retry-trend] FATAL:', err);
  process.exit(1);
});
