"use strict";
// prepack guard — fail the publish if any packed path is gitignored
// (repo + global). `--ignore-scripts` on the inner pack call avoids
// re-triggering this hook.

var cp = require("node:child_process");

function _run(cmd, args, opts) {
  return cp.spawnSync(cmd, args, Object.assign({ encoding: "utf8" }, opts || {}));
}

function main() {
  // shell-form: Node 22+ rejects spawning npm.cmd directly on Windows,
  // and `shell: true` with a separate args array trips DEP0190.
  var pack = _run("npm pack --dry-run --ignore-scripts --json", [], { shell: true });
  if (pack.status !== 0) {
    process.stderr.write("[prepack-guard] npm pack --dry-run failed:\n");
    process.stderr.write(pack.stderr || "");
    process.exit(1);
  }
  var info;
  try { info = JSON.parse(pack.stdout); }
  catch (_e) {
    process.stderr.write("[prepack-guard] could not parse npm pack output\n");
    process.exit(1);
  }
  var entry = Array.isArray(info) ? info[0] : info;
  var files = (entry && entry.files) || [];
  if (files.length === 0) {
    process.stderr.write("[prepack-guard] npm pack reported zero files\n");
    process.exit(1);
  }
  var paths = files.map(function (f) { return f.path; });

  var check = _run("git", ["check-ignore", "--verbose", "--no-index", "--stdin"], {
    input: paths.join("\n") + "\n",
  });

  if (check.status === 1) {
    process.stdout.write(
      "[prepack-guard] ok — " + paths.length + " paths checked, none gitignored\n"
    );
    return;
  }
  if (check.status !== 0) {
    process.stderr.write("[prepack-guard] git check-ignore failed:\n");
    process.stderr.write(check.stderr || "");
    process.exit(1);
  }

  var lines = (check.stdout || "").split("\n").filter(Boolean);
  process.stderr.write("[prepack-guard] gitignored paths in tarball:\n");
  lines.forEach(function (l) { process.stderr.write("  " + l + "\n"); });
  process.exit(1);
}

main();
