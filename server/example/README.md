# Example datasets & how to run

Data is not bundled. Prepare the required files, start the server if needed (`python server/run_server.py 9000`), then run the scripts from `server/example/`.

- **ex0_ip.py** — pure HE inner-product sanity check; no external data or server required.  
  `python ex0_ip.py`

- **ex1_deep1m.py** — Deep1M FBIN vectors. Download `deep1M_base.fbin` and `deep1M_query.fbin`, then:  
  `python ex1_deep1m.py deep1M_base.fbin deep1M_query.fbin`  
  Defaults: uses first 1M base and 10k queries.

- **ex2_laion.py** — LAION image/text embeddings as NumPy arrays. Provide two `.npy` files (image and text embeddings).  
  `python ex2_laion.py img_emb.npy text_emb.npy`  
  Defaults: first 100k image / 1k text vectors.

- **ex3_locomo.py** — Locomo QA retrieval with NVIDIA Dragon encoder. Requires:  
  - `--qa_json` : QA pairs JSON  
  - `--memory_db_root` : directory containing plaintext vector collections (`vector.npz`, `meta.json`)  
  Example:  
  `python ex3_locomo.py --qa_json .db/locomo/base/json_data/qa.json --memory_db_root .db/locomo/base/dense/memory_dragon_naive.db`
  GPU recommended for encoder; downloads model via `transformers`.

Tips
- Ensure `hevec_py` is built/installed before running any script that imports it.
- For fresh runs, collections are dropped/recreated by the scripts; this is expected.
