# HEVEC Node.js Binding

This directory hosts the Electron/Node.js bindings for the `HEVEC` C++ library.
They mirror the Python bindings provided in `python/bindings.cpp`, exposing the
same HE-friendly APIs via N-API.

## Prerequisites

- CMake 3.21+
- A C++20 toolchain (clang or gcc) with OpenMP support
- Python 3 (needed only when CMake downloads Intel HEXL)
- `git` (required to fetch Intel HEXL)
- OpenSSL development headers
- Node.js 20+ (matching the Electron runtime used by this project)

Install the project dependencies so the header-only `node-addon-api` and
`cmake-js` utilities are available:

```bash
cd frontend
npm install
```

## Building the native module

```
cd frontend
npm run build:hevec-native
```

The script runs `cmake-js build` inside `src/encryption/HEVEC`, enabling the
`BUILD_NODE` flag. It produces `frontend/src/encryption/HEVEC/build/Release/hevec_node.node`
(and the Debug variant when built with `--debug`). The CMake build reuses the
same sources/libraries as the Python module, including pulling Intel HEXL when
`BUILD_HEXL=ON` (default).

If the Electron runtime or architecture differs from your local defaults, pass
additional flags manually, for example:

```bash
npx cmake-js build \
  --directory src/encryption/HEVEC \
  --CD BUILD_NODE=ON \
  --runtime electron \
  --runtime-version 38.1.2 \
  --arch x64
```

Set `HEVEC_NODE_ADDON_PATH` to override the module lookup path if you relocate the
built `.node` file.

## Using the binding

The TypeScript entry point `index.ts` resolves the compiled addon and exports
all bound classes/functions with strong typings from `types.d.ts`:

```ts
import { Client, Message, SecretKey } from './node';

const client = new Client(7);
const secret = new SecretKey();
client.genSecKey(secret);
```

Ensure the native module is present (via the build step above) before bundling
or running the Electron processes that import it.
