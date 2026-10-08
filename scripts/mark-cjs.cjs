// The package is "type": "module", so Node reads every .js file in it as ESM unless a
// nearer package.json says otherwise. This marks the CommonJS build as CommonJS, so
// require('@getparafe/sdk') works, and TypeScript reads the .d.ts files beside it as
// CommonJS declarations (CODE_REVIEW P-48).
const { writeFileSync } = require('node:fs');
writeFileSync('dist/cjs/package.json', '{ "type": "commonjs" }\n');
