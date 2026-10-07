# convert-npdm

Convert Nintendo Switch `.npdm` files to JSON and back.

## Usage

```sh
npx convert-npdm parse main.npdm main.json   # NPDM -> JSON (prints to stdout if no output)
npx convert-npdm build main.json main.npdm   # JSON -> NPDM
```

## Library

```ts
import { readFile, writeFile } from "node:fs/promises";
import { parseNpdm, buildNpdm } from "convert-npdm";

const { json, warnings } = parseNpdm(await readFile("main.npdm"));
await writeFile("main.npdm", buildNpdm(json).bytes);
```