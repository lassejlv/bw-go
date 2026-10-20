// Converts an upstream spec-data module (libs/importer/src/importers/spec-data/**.ts) into plain
// files so Go tests can embed them. Run with bun (it imports TypeScript directly):
//
//   bun internal/importer/testdata/extract-spec-data.mjs <spec-data file.ts> <output dir>
//
// Every exported string is written to <output dir>/<ExportName>.txt verbatim; every other export
// (objects, arrays) is written as <output dir>/<ExportName>.json. Type-only imports in the module
// are erased by bun; if a module imports runtime values from @bitwarden/*, copy the literal by
// hand instead.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";

const [src, out] = process.argv.slice(2);
if (!src || !out) {
  console.error("usage: bun extract-spec-data.mjs <spec-data.ts> <outdir>");
  process.exit(2);
}
const mod = await import(resolve(src));
mkdirSync(out, { recursive: true });
for (const [name, value] of Object.entries(mod)) {
  if (typeof value === "string") {
    writeFileSync(join(out, `${name}.txt`), value);
  } else {
    writeFileSync(join(out, `${name}.json`), JSON.stringify(value, null, 2));
  }
  console.log(`${name} -> ${join(out, name)}`);
}
