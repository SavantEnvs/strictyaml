#!/usr/bin/env python3
"""Atheris fuzz harness for strictyaml.

Exercises the strictyaml parser/round-trip on arbitrary input. Atheris
instruments the imported strictyaml package (coverage), so libFuzzer drives the
parser toward new code paths.

Run modes (driven by the compiled launcher `strictyaml_fuzzer` / `-standalone`):
  * fuzzing      - `python3 fuzz_yaml.py [libFuzzer args]`
  * single input - `python3 fuzz_yaml.py <file>` (libFuzzer runs it once)
"""
import os
import sys

import atheris

import fuzz_helpers

# libFuzzer fork mode (-fork=N, which Mayhem uses) re-execs sys.argv[0] to spawn
# each child job. Launched via the compiled ELF launcher, sys.argv[0] is this
# script, and its `#!/usr/bin/env python3` shebang re-exec depends on `python3`
# being on PATH. Mayhem runs the target with a restricted PATH that lacks python3,
# so every fork child dies at exec ("env: python3: No such file", exit 127) => the
# run records 0 edges / Run Failed, even though the single-process smoketest (driven
# through the launcher's absolute interpreter) succeeds. Point sys.argv[0] back at
# the launcher ELF so each fork child re-execs the PATH-independent launcher (which
# has the absolute interpreter baked in at build time) instead of the env-shebang.
_LAUNCHER = os.environ.get("STRICTYAML_FUZZER_LAUNCHER", "/mayhem/strictyaml_fuzzer")
if os.path.exists(_LAUNCHER):
    sys.argv[0] = _LAUNCHER

# Instrument ONLY the library under test (scope the include list so import time
# stays low in libFuzzer fork mode - a bare instrument_imports() would pull in
# hundreds of stdlib modules and stall every fork child at startup).
with atheris.instrument_imports(include=["strictyaml"]):
    import strictyaml

# The only documented input-rejection exception: strictyaml.YAMLError is raised
# by design for YAML the library declines to parse. Everything else that escapes
# construct_mapping/scanner/composer (NotImplementedError "overlap in comment",
# TypeError on unhashable/None comment state, bare AssertionError, RecursionError
# on deep nesting, ...) is an unhandled exception INSIDE strictyaml's own vendored
# ruamel code — a genuine defect in the target, not a harness artifact — and must
# be left to propagate so Mayhem records it.
_BENIGN_INPUT_ERRORS = (strictyaml.YAMLError,)


def TestOneInput(data: bytes) -> None:
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    test = fdp.ConsumeIntInRange(0, 2)
    try:
        if test == 0:
            # Parse arbitrary YAML and materialize the resulting data.
            strictyaml.load(fdp.ConsumeRemainingString()).data
        elif test == 1:
            # Parse then round-trip back to YAML.
            obj = strictyaml.load(fdp.ConsumeRemainingString())
            obj.as_yaml()
        elif test == 2:
            # Build a fuzzed dict and serialize it as a YAML document.
            fuzz_dict = fuzz_helpers.build_fuzz_dict(fdp, [str, str])
            strictyaml.as_document(fuzz_dict).as_yaml()
    except _BENIGN_INPUT_ERRORS:
        # Malformed / non-conforming / unsupported YAML — rejected by design.
        return -1


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
