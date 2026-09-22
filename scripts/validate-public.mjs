import fs from "node:fs";
const source=fs.readFileSync(new URL("../public/app.js",import.meta.url),"utf8");
const bad=[...source.matchAll(/(?<!\$)\$\("\[[^"]+\]"\)\.forEach/g)].map(x=>x[0]);
if(bad.length){console.error("Invalid single-element selector used with forEach:",bad);process.exit(1)}
if(source.includes('restore();\\n[')){console.error("Literal patch newline artifact found in public/app.js");process.exit(1)}
console.log("Public browser UI validation passed");
