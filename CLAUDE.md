# Rules for Claude

- Never use mock, synthetic, fake, or placeholder data: not in tests, examples,
  outputs, or reports. Only run against real sources. If a real source is
  unreachable (network policy, bot protection, missing access), stop and report
  exactly what is blocked instead of substituting made-up data.
