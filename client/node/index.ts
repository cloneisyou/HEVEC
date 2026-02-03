import { existsSync } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

import type { HEVECBinding } from './types';

const require = createRequire(import.meta.url);

function findFrontendRoot(start: string): string {
  let current = start;
  while (!existsSync(path.join(current, 'package.json'))) {
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return current;
}

const frontendRoot = findFrontendRoot(__dirname);
const buildDir = path.resolve(frontendRoot, 'src/encryption/HEVEC/build');

const candidates = [
  path.join(buildDir, 'Release', 'hevec_node.node'),
  path.join(buildDir, 'Debug', 'hevec_node.node'),
  path.resolve(frontendRoot, 'build', 'Release', 'hevec_node.node'),
  path.resolve(frontendRoot, 'build', 'Debug', 'hevec_node.node'),
];

if (process.env.HEVEC_NODE_ADDON_PATH) {
  candidates.unshift(process.env.HEVEC_NODE_ADDON_PATH);
}

const addonPath = candidates.find((candidate) => existsSync(candidate));

if (!addonPath) {
  throw new Error(
    'Failed to locate hevec_node native module. run `npm run build:hevec-native` before importing this package.',
  );
}

const binding = require(addonPath) as HEVECBinding;

export default binding;

export const {
  Message,
  Polynomial,
  SecretKey,
  SwitchingKey,
  MLWESwitchingKey,
  AutedModPackKeys,
  AutedModPackMLWEKeys,
  Ciphertext,
  MLWECiphertext,
  CachedQuery,
  CachedKeys,
  TopK,
  Client,
  Server,
  HEVECClient,
  MetricType,
  getTopKIndices,
} = binding;
