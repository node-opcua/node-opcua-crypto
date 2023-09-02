import resolve from '@rollup/plugin-node-resolve';
import nodePolyfills from 'rollup-plugin-polyfill-node';
import commonjs from "rollup-plugin-commonjs";

export default {

    input: './web/main.js',
    output: {
        file: './web/bundle.js',
        format: 'esm'
    },
    plugins: [resolve(), nodePolyfills({
        include: ['crypto'],
        crypto: true,
        assert: true,
    }),
    commonjs({ sourceMap: false })
    ]
};

