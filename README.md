# HEVEC

HEVEC (Homomorphically Encrypted VECtor database): end‑to‑end encrypted similarity search where queries stay MLWE-encrypted throughout the client ↔ server lifecycle. HEVEC aims to remove the privacy bottleneck for personal AI agents (e.g., OpenClaw‑style copilots) by keeping both data and queries encrypted even during computation.

## Why HEVEC
- Secure alternative to plaintext vector databases: data and queries remain encrypted end to end via homomorphic encryption—only the user can decrypt results.
- Real-time encrypted search at scale: demonstrated ~1M vectors in ~187 ms while preserving privacy.
- System-level privacy by design: aligned with the principle that deeply personalized agents must leave data ownership with users; already serving as a core privacy component in real deployments (e.g., Clone multimodal memory assistant).

## Architecture

```mermaid
flowchart LR
    subgraph Client
        A[Keygen<br/>SecretKey / SwitchingKey]
        B[Encrypt query
        (MLWE)]
        C[Decrypt scores]
    end

    subgraph Server
        D[HEVEC Server<br/>C++20 + HEXL]
        E[Vector Collections<br/>HE-friendly layout]
    end

    A --> B
    B -->|encrypted query| D
    E --> D
    D -->|encrypted scores| C
```

## Requirements

- CMake ≥ 3.21, C++20 toolchain with OpenMP and OpenSSL dev headers (clang‑17/llvm from `server/conda/HEVEC-dev.yml` is known-good)
- Python 3.10+ for bindings and examples
- Node.js 20+ if building the N-API addon (`client/node`)
- Git network access (CMake fetches Intel HEXL when `BUILD_HEXL=ON`, default)

You can reproduce the tested toolchain via Conda:

```bash
conda env create -f server/conda/HEVEC-dev.yml
conda activate HEVEC-dev
```

## Build & Install

### Core library + Python binding

```bash
cd server
cmake -S . -B build -DBUILD_PYTHON=ON
cmake --build build --config Release
# Optionally install the pybind module in editable mode
pip install -e .
```

### Node.js binding (optional)

```bash
cd client/node
npm install
npm run build:hevec-native
```

### (Optional) TCP transport (legacy-compatible)

The default transport is HTTP/Beast. TCP support now lives in the main tree (no separate `legacy_for_tcp/`). Enable it only if you need the older socket protocol:

```bash
cd server
cmake -S . -B build -DBUILD_TCP_BACKEND=ON
cmake --build build --config Release
```
Use the `HEVECClientTCP` and `HEVECServerTCP` classes from `HEVEC/HEVECClientTCP.hpp` and `HEVEC/HEVECServerTCP.hpp` respectively.

### Build options (CMake)

| Option               | Default | Description |
|----------------------|---------|-------------|
| `BUILD_PYTHON`       | OFF     | Build Python bindings (`hevec_py`). |
| `BUILD_NODE`         | OFF     | Build Node/Electron addon (`hevec_node`). |
| `BUILD_TCP_BACKEND`  | OFF     | Include legacy TCP client/server classes. |
| `BUILD_HEXL`         | ON      | Fetch/build Intel HEXL; set OFF to link a system copy. |

## Run the server

Start the standalone server on port 9000:

```bash
cd server
python run_server.py 9000
```

The server exposes the HEVEC protocol used by the client examples below.

### Defaults and environment
- Default port: `9000`
- AES key path (optional, TCP PIR payload encryption): set `HEVEC_AES_KEY_PATH` to load/save AES key.
- Client log file (optional): set `HEVEC_CLIENT_LOG_PATH` to append client-side timings.

## Reproduce the examples

All scripts live under `server/example/`. Ensure the server is running (`python run_server.py 9000`) when an example uses `HEVECClient`.

- `ex0_ip.py` — Pure HE inner-product sanity check; no server required. Run: `python server/example/ex0_ip.py`.
- `ex1_deep1m.py <base.fbin> <query.fbin>` — Encrypted search over Deep1M FBIN files. Truncates to 1M base / 10k queries by default.
- `ex2_laion.py <img_emb.npy> <text_emb.npy>` — Cross-modal LAION evaluation using precomputed embeddings (100k/1k default subset).
- `ex3_locomo.py --qa_json <qa.json> --memory_db_root <dense_db_dir>` — Locomo QA retrieval; loads plaintext vectors from `memory_db_root`, inserts into HEVEC, compares encrypted vs. plaintext scores. Requires the NVIDIA Dragon encoder (downloads via `transformers`).

Data is not bundled. Use the paths in each example’s usage string and supply your own embeddings/FBIN files. GPU is recommended for `ex3_locomo.py` due to transformer inference.

## Citation

```
@article{bae2025privacy,
  title={Privacy-Preserving LLM Interaction with Socratic Chain-of-Thought Reasoning and Homomorphically Encrypted Vector Databases},
  author={Bae, Yubeen and Kim, Minchan and Lee, Jaejin and Kim, Sangbum and Kim, Jaehyung and Choi, Yejin and Mireshghallah, Niloofar},
  journal={arXiv preprint arXiv:2506.17336},
  year={2025}
}
```
