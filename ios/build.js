/* Build locally; Surge downloads only the self-contained generated script. */
'use strict';
const esbuild = require('esbuild');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
fs.mkdirSync(path.join(root, 'module'), { recursive: true });
esbuild.buildSync({
  entryPoints: [path.join(__dirname, 'entry.js')],
  outfile: path.join(root, 'module/surge-vless.js'),
  bundle: true,
  platform: 'browser',
  format: 'iife',
  target: ['safari16'],
  minify: true,
  legalComments: 'eof',
  loader: { '.html': 'text' },
  banner: { js: '/* Surge VLESS Importer 0.2.0 beta | Local-only conversion | Bundled yaml: ISC license, see THIRD_PARTY_NOTICES.md */' },
});
console.log('Built module/surge-vless.js (' + fs.statSync(path.join(root, 'module/surge-vless.js')).size + ' bytes)');
