module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': 'off',
    // Allow unused vars with underscore prefix
    '@typescript-eslint/no-unused-vars': ['warn', {
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
    }],
    // Allow any for API responses (TODO: add proper types later)
    '@typescript-eslint/no-explicit-any': 'off',
    // React hooks deps - warn only, not error
    'react-hooks/exhaustive-deps': 'off',
  },
}
