/**
 * Ambient declarations for the untyped security plugins.
 *
 * These packages ship plain JavaScript with no bundled types, and `declare
 * module` cannot augment a module that resolves to an untyped JS file, so the
 * declarations live in their own .d.ts where a bare `declare module` is allowed.
 *
 * Kept narrow on purpose: only the surface this scanner touches, so a typo in
 * `rules` or `configs` is still a compile error.
 */
declare module 'eslint-plugin-security' {
  import type { Linter } from 'eslint';
  const plugin: {
    rules?: Linter.RulesRecord;
    configs?: Record<string, { rules?: Linter.RulesRecord }>;
  };
  export default plugin;
}

declare module 'eslint-plugin-no-unsanitized' {
  import type { Linter } from 'eslint';
  const plugin: {
    rules?: Linter.RulesRecord;
    configs?: Record<string, { rules?: Linter.RulesRecord }>;
  };
  export default plugin;
}