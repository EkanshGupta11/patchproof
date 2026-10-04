#!/usr/bin/env node
/**
 * Fake document converter.
 *
 * Stands in for a real CLI tool (ImageMagick's `convert`, `ffmpeg`, `pandoc`)
 * so the demo has no external dependencies. It simply reports what it was asked
 * to convert.
 *
 * This file is intentionally NOT part of src/ and is not the vulnerability --
 * the bug is that the /convert route builds a shell command out of user input.
 */
const args = process.argv.slice(2);

function flag(name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  return value === undefined ? fallback : value;
}

const format = flag('--format', 'txt');
const input = flag('--input', 'input.txt');

console.log(`converted ${input} -> ${format}`);
