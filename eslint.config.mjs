import tsEslint from 'typescript-eslint';
import jest from 'eslint-plugin-jest';
import stylisticTs from '@stylistic/eslint-plugin-ts';

export default [
    ...tsEslint.config({
        extends: [...tsEslint.configs.recommended],
        files: ['**/*.ts'],
        ignores: ['lib/**/*', '**/*.d.ts', '**/*.mjs', '**/*.js'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            parser: tsEslint.parser,
            parserOptions: {
                ecmaVersion: "latest",
                sourceType: "module",
                project: './tsconfig.eslint.json',
            },
        },
        plugins: {
            'jest': jest,
            '@stylistic/ts': stylisticTs,
        },
        rules: {
            '@stylistic/ts/indent': ['error', 4],
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    'args': 'all',
                    'argsIgnorePattern': '^_',
                    'caughtErrors': 'all',
                    'caughtErrorsIgnorePattern': '^_',
                    'destructuredArrayIgnorePattern': '^_',
                    'varsIgnorePattern': '^_',
                    'ignoreRestSiblings': true
                }
            ],
            '@typescript-eslint/no-namespace': 'off',
        },
    })
];
