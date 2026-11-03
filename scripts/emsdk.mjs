// Provides a pinned Emscripten SDK for the wasm32-unknown-emscripten target.
// Cargo cannot install emcc (a Python/Clang/Binaryen toolchain), so this uses
// emcc from PATH when present, else $EMSDK, else a per-user cached install.
//
//   node scripts/emsdk.mjs            # install if missing, print shell exports
//   eval "$(node scripts/emsdk.mjs)"  # then cargo --target wasm32-unknown-emscripten
//
// shortcut: POSIX only (./emsdk, ':' PATH separator); add emsdk.bat for Windows.
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const VERSION = '6.0.10';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: ['ignore', 2, 2], ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed (${result.status})`);
}

/** Environment in which `emcc` resolves; installs the pinned SDK on first use. */
export function emscriptenEnv(env = process.env) {
  if (spawnSync('emcc', ['--version'], { stdio: 'ignore', env }).status === 0) return env;
  const cache = env.XDG_CACHE_HOME || join(homedir(), '.cache');
  const root = env.EMSDK || join(cache, 'guac', `emsdk-${VERSION}`);
  const emcc = join(root, 'upstream', 'emscripten');
  if (!existsSync(join(emcc, 'emcc'))) {
    console.error(`Installing Emscripten ${VERSION} into ${root} (about 1.7 GB, once)…`);
    if (!existsSync(join(root, 'emsdk')))
      run('git', ['clone', '--depth', '1', '--branch', VERSION, 'https://github.com/emscripten-core/emsdk', root]);
    run('./emsdk', ['install', VERSION], { cwd: root });
    run('./emsdk', ['activate', VERSION], { cwd: root });
  }
  return { ...env, EMSDK: root, EM_CONFIG: join(root, '.emscripten'), PATH: `${emcc}:${env.PATH ?? ''}` };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const env = emscriptenEnv();
  for (const name of ['EMSDK', 'EM_CONFIG', 'PATH'])
    if (env[name] !== undefined && env[name] !== process.env[name]) console.log(`export ${name}='${env[name]}'`);
}
