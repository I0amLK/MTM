# F6: shared public command contract for resource comparison

The capable-host resource run at `af2b4e2041e303e622b22719834495e4f1ef62a7`
failed before producing resource metrics. Its exact receipt is preserved as
`records/evidence/MTM-016/candidate-resource-f6-af2b4e2-failed.json`.
The operator's focused rerun returned `MCP protocol failure` after 2.48 seconds.
Neither observation establishes a performance regression or successful sampling.

## Root cause and bounded reproduction

The resource fixture sent an `argv`-only `exec_command` request. The reviewed
`0.5.0-preview.2` baseline's real `tools/list` schema requires `cmd` and does not
advertise `argv`. The current candidate permits either form, exclusively. The
baseline returned JSON-RPC `-32602` with `data.reason=invalid_arguments` for the
old fixture, before Native execution. The common client deliberately converted
that error to the fixed `MCP protocol failure` message without publishing bodies.

Two regressions failed with the old request. The corrected fixture sends the
identical public request to both artifacts:

```json
{"cmd":"/usr/bin/printf resource-ok","yield_time_ms":30000}
```

There is no baseline-only adapter, retry, fallback, product schema change or
private executor call. The shell source is a fixed literal with an absolute
executable, no user interpolation and no PATH expansion. Each product retains its
own implementation of the public `cmd` contract; this does not claim that the
two versions have identical shell internals.

The endpoint regression uses disposable OAuth/MCP servers with Native disabled.
Both the exact baseline and exact frozen candidate accept the common request
through their public schema and return `NATIVE_ISOLATION_REQUIRED` at the real
Native authority boundary. Four invalid requests per endpoint remain schema
errors: missing command, empty command, conflicting `cmd`/`argv`, and an unknown
property. These are compatibility and rejection observations, not Native
execution, resource samples, human consent or release evidence. Ordinary source
tests exercise the Cargo-built candidate; the baseline is only used when both
existing explicit baseline-selection variables are supplied.

## Unchanged qualification requirements

Both versions still use the same resource server configuration, three starts and
70 alternating requests per start, discarding ten warmup requests per start.
Each must supply 180 measured requests with the original latency, RSS, thread,
file-descriptor and shutdown bounds. No child may remain after a measured
request. Successful Native responses now also explicitly require `status=exited`.
The percentile calculation, thresholds and Rust receipt/summary validators are
unchanged. Fixed failure-only stage labels identify baseline/candidate startup,
login, command, server information, process sampling, children, shutdown or
comparison failures without echoing tokens, commands or response bodies.

## Evidence and next acceptance

The failure receipt is unchanged. The old successful source, Native, compiled
LaTeX and target receipts are not rewritten. This integration-test amendment does
change the raw source/harness hash: the previous source result remains an honest
observation of its own checkout, but a new complete source run is required for
the current checkout. Release-check is not modified to waive this requirement.
The frozen candidate and baseline binaries are not rebuilt or replaced.

On a stable committed checkout, rerun `cargo xtask check --record`, followed by
`cargo xtask qualify --profile resource` with the same explicit candidate and
baseline paths and digests. Preserve any new failure; do not relax thresholds or
run concurrent compilation or stress tests during resource measurement.
