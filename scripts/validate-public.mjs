import fs from "node:fs";
const source=fs.readFileSync(new URL("../public/app.js",import.meta.url),"utf8");
const html=fs.readFileSync(new URL("../public/index.html",import.meta.url),"utf8");
const bad=[...source.matchAll(/(?<!\$)\$\("\[[^"]+\]"\)\.forEach/g)].map(x=>x[0]);
if(bad.length){console.error("Invalid single-element selector used with forEach:",bad);process.exit(1)}
if(source.includes('restore();\\n[')){console.error("Literal patch newline artifact found in public/app.js");process.exit(1)}
const pages=[...html.matchAll(/data-page="([^"]+)"/g)].map(x=>x[1]);
const missingPages=[...new Set(pages)].filter(page=>!html.includes('id="'+page+'Page"'));
if(missingPages.length){console.error("Navigation pages missing matching sections:",missingPages);process.exit(1)}
const requiredIds=["metricGrid","progressPanel","progressBody","controlsBody","evidenceGrid","assessmentsBody","findingBoard","integrationGrid","auditBody","manualContent","modal","toast"];
const missingIds=requiredIds.filter(id=>!html.includes('id="'+id+'"'));
if(missingIds.length){console.error("Critical UI containers missing:",missingIds);process.exit(1)}
const ids=[...html.matchAll(/\sid="([^"]+)"/g)].map(x=>x[1]);
const duplicates=ids.filter((id,i)=>ids.indexOf(id)!==i);
if(duplicates.length){console.error("Duplicate DOM ids found:",[...new Set(duplicates)]);process.exit(1)}
console.log("Public browser UI validation passed");
