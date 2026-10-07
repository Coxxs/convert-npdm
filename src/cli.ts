#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { buildNpdm, parseNpdm } from "./index.ts";

const USAGE = `Usage:
  npdm parse <input.npdm> [output.json]   NPDM -> JSON (stdout if no output)
  npdm build <input.json> <output.npdm>   JSON -> NPDM`;

async function main(argv: string[]): Promise<number> {
  const [command, input, output, ...extra] = argv;
  if (command === "-h" || command === "--help") {
    console.log(USAGE);
    return 0;
  }
  if ((command !== "parse" && command !== "build") || !input || extra.length) {
    console.error(USAGE);
    return 1;
  }
  if (command === "build" && !output) {
    console.error("error: build requires an output path\n\n" + USAGE);
    return 1;
  }

  let data: Buffer;
  try {
    data = await readFile(input);
  } catch (err) {
    console.error(`error: ${(err as Error).message}`);
    return 1;
  }

  const isNpdm = data.subarray(0, 4).toString("latin1") === "META";
  if (command === "parse" && !isNpdm) {
    console.error(`error: ${input} is not an NPDM file (missing META magic). Did you mean \`npdm build\`?`);
    return 1;
  }
  if (command === "build" && isNpdm) {
    console.error(`error: ${input} is an NPDM file, not JSON. Did you mean \`npdm parse\`?`);
    return 1;
  }

  let out: string | Uint8Array;
  let warnings: string[];
  try {
    if (command === "parse") {
      const result = parseNpdm(data);
      out = JSON.stringify(result.json, null, "\t") + "\n";
      warnings = result.warnings;
    } else {
      const result = buildNpdm(JSON.parse(data.toString("utf8")));
      out = result.bytes;
      warnings = result.warnings;
    }
  } catch (err) {
    console.error(`error: ${input}: ${(err as Error).message}`);
    return 1;
  }

  for (const w of warnings) console.error(`warning: ${w}`);

  if (!output) {
    process.stdout.write(out);
    return 0;
  }
  try {
    await writeFile(output, out);
  } catch (err) {
    console.error(`error: ${(err as Error).message}`);
    return 1;
  }
  return 0;
}

process.exitCode = await main(process.argv.slice(2));
