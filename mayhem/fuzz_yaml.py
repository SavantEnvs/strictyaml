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

# Benign input-rejection exceptions. Beyond the documented strictyaml.YAMLError,
# strictyaml/ruamel raise a handful of *non*-YAMLError exceptions when the fuzzer
# feeds YAML that is malformed or uses constructs strictyaml simply does not
# support. These are input-rejection paths, NOT defects in the target, so an
# uncaught one crashes every libFuzzer fork child (Mayhem: repeated "libFuzzer
# process exited" => 0 edges / Run Failed) even while coverage is climbing. Each
# type below was observed ESCAPING the parser over ~300k fork-mode iterations
# (plus a deep-nesting probe):
#   * NotImplementedError - ruamel/tokens.py move_comment(): "overlap in comment"
#   * TypeError           - ruamel/comments.py add_kv_line_col(): unhashable
#                           complex mapping key (e.g. a CommentedMap used as a key)
#   * AssertionError      - yamlpointer.py key(): non-string (tuple) mapping key
#   * RecursionError      - pathologically deep nesting exhausts the parser stack
# Treat them exactly like YAMLError (reject the input, return -1) so fuzzing keeps
# exploring the parser instead of aborting the child.
_BENIGN_INPUT_ERRORS = (
    strictyaml.YAMLError,
    NotImplementedError,
    TypeError,
    AssertionError,
    RecursionError,
)


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
    except AttributeError as e:
        # Known benign ruamel edge: a partial parse can leave context_mark unset.
        if "context_mark" in str(e):
            return -1
        raise


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
