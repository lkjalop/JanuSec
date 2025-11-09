export default [
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'module'
    },
    ignores: ['static/js/*.bundle.js', 'static/js/*.min.js', 'static/js/csv_analyzer.js', 'static/js/test_helpers.js'],
    rules: {
      'no-unused-vars': ['error', { 'argsIgnorePattern': '^_', 'varsIgnorePattern': '^_', 'caughtErrors': 'none' }],
      'no-console': 'off'
    }
  }
];
