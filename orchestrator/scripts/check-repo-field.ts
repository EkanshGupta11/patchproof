/**
 * Checks for the dashboard repo field's input normalisation.
 *
 * The field accepts a pasted browser URL as readily as "owner/name", so the
 * normalisation rules are the part most likely to be wrong in a way that is
 * annoying rather than fatal: silently storing "https://github.com/acme/shop/tree/main"
 * as a repo would only fail much later, when the PR call does.
 */
import assert from 'node:assert/strict';
import { normaliseRepoInput } from '../src/github.js';
import {
  clearTargetRepo,
  currentTargetRepo,
  isTargetRepoOverridden,
  setTargetRepo,
} from '../src/githubTargetRepo.js';
import { config } from '../src/config.js';

let failed = 0;

function check(label: string, condition: boolean): void {
  console.log(`  ${condition ? 'PASS' : 'FAIL'}  ${label}`);
  if (!condition) failed += 1;
}

/** Normalises, or returns the error message so a rejection can be asserted. */
function normalise(input: string): { ok: true; value: string } | { ok: false; error: string } {
  try {
    return { ok: true, value: normaliseRepoInput(input) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

console.log('1. accepted forms all reduce to owner/name');
const ACCEPTED: Array<[string, string]> = [
  ['acme/shop', 'acme/shop'],
  ['  acme/shop  ', 'acme/shop'],
  ['https://github.com/acme/shop', 'acme/shop'],
  ['http://github.com/acme/shop', 'acme/shop'],
  ['https://www.github.com/acme/shop', 'acme/shop'],
  ['github.com/acme/shop', 'acme/shop'],
  ['https://github.com/acme/shop.git', 'acme/shop'],
  ['https://github.com/acme/shop/', 'acme/shop'],
  ['git@github.com:acme/shop.git', 'acme/shop'],
  // The browser address bar for a subpage, which is what people actually paste.
  ['https://github.com/acme/shop/tree/main', 'acme/shop'],
  ['https://github.com/acme/shop/pull/42', 'acme/shop'],
  // Dots, dashes and underscores are legal in repo names.
  ['acme/my.shop', 'acme/my.shop'],
  ['ac-me/shop_v2', 'ac-me/shop_v2'],
  ['acme/shop.js', 'acme/shop.js'],
  // Sub-pages are truncated rather than rejected: these all clearly name
  // acme/shop, and refusing them would just make the user trim the URL by hand.
  ['https://github.com/acme/shop/tree/main/src', 'acme/shop'],
  ['https://github.com/acme/shop?tab=readme', 'acme/shop'],
  ['https://github.com/acme/shop#readme', 'acme/shop'],
  // A stray slash is a formatting slip, not a different intent.
  ['acme//shop', 'acme/shop'],
];

for (const [input, expected] of ACCEPTED) {
  const result = normalise(input);
  check(`${JSON.stringify(input)} -> ${expected}`, result.ok && result.value === expected);
}

console.log('\n2. rejected inputs, with a message meant to be read');
const REJECTED = [
  '',
  '   ',
  'acme',
  'https://github.com/acme',
  'a/b/c',
  'acme / shop',
  '-acme/shop',
  // A different host cannot be mapped onto owner/name.
  'https://gitlab.com/acme/shop',
];

for (const input of REJECTED) {
  const result = normalise(input);
  check(
    `${JSON.stringify(input)} rejected`,
    !result.ok && result.error.length > 0,
  );
}

// The message is shown verbatim in the UI, so it must not leak JSON or a stack.
const emptyResult = normalise('');
check('empty input explains what to type', !emptyResult.ok && /owner\/name/i.test(emptyResult.error));
check('empty input error is readable', !emptyResult.ok && !emptyResult.error.includes('{'));

console.log('\n3. override precedence');
clearTargetRepo();
check(
  'with no override, the .env default is used',
  currentTargetRepo() === config.github.defaultRepo,
);
check('no override means not overridden', isTargetRepoOverridden() === false);

setTargetRepo('acme/other');
check('override wins over .env', currentTargetRepo() === 'acme/other');
check(
  'an override different from .env reads as overridden',
  isTargetRepoOverridden() === (config.github.defaultRepo !== 'acme/other'),
);

clearTargetRepo();
check('clearing restores the .env default', currentTargetRepo() === config.github.defaultRepo);
check('clearing clears the overridden flag', isTargetRepoOverridden() === false);

console.log(
  failed === 0 ? '\n  ok  repo input normalisation is correct' : `\n  ${failed} check(s) FAILED`,
);
if (failed > 0) process.exit(1);