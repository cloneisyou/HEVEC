"""Standalone evaluation script for Locomo QA retrieval using Dragon embeddings.
This script evaluates the precision of the HEVEC system by comparing its search
results against a plaintext ground truth, similar to `ex0_deep1m.py`.

The script makes **no** dependency on the root-level ``src`` package so that it can be
executed from inside the ``HEVEC/example`` folder just like the other demo scripts.

Workflow
---------
1. Connect to a running HEVEC server.
2. Set up collections on the HEVEC server:
   a. Iterates through all user collections in the ``memory_db_root``.
   b. For each collection, drops any existing one on the server.
   c. Reads plaintext vectors and inserts them into the new HEVEC collection.
3. For each question in the QA data:
   a. Embed the question to get a query vector.
   b. **HEVEC Query**: Get predicted scores from the HEVEC server.
   c. **Ground Truth**: Calculate exact scores locally via dot product.
   d. Compare the two score sets to measure error and ranking accuracy.

**NOTE**: An HEVEC server instance must be running before executing this script.

Usage
-----
```bash
# First, run the server in a separate terminal:
# python HEVEC/example/run_server.py

# Then, run this evaluation script:
python ex2_locomo.py \
  --qa_json .db/locomo/base/json_data/qa.json \
  --memory_db_root .db/locomo/base/dense/memory_dragon_naive.db
```
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List

import numpy as np
import torch  # type: ignore
from transformers import AutoModel, AutoTokenizer  # type: ignore

import hevec_py

# -------------------------------------------------- Dragon Embedding

IS_QUERY_ENCRYPT = False


class DragonQueryEncoder:
    """Wrapper around the NVIDIA Dragon query encoder to return NumPy embeddings."""

    _MODEL_NAME = "nvidia/dragon-multiturn-query-encoder"

    def __init__(self) -> None:
        self.tokenizer = AutoTokenizer.from_pretrained(self._MODEL_NAME)
        self.model = AutoModel.from_pretrained(self._MODEL_NAME)

        # Determine embedding dimension once
        with torch.no_grad():
            sample = self.tokenizer("hello", return_tensors="pt")
            self._dim = self.model(**sample).last_hidden_state.size(-1)

    @property
    def dim(self) -> int:
        return self._dim

    def __call__(self, texts: List[str]) -> np.ndarray:
        inputs = self.tokenizer(texts, padding=True, truncation=True, return_tensors="pt")
        with torch.no_grad():
            outputs = self.model(**inputs).last_hidden_state[:, 0, :]  # CLS token
        return outputs.cpu().numpy().astype("float32")


# -------------------------------------------------- Naive Vector DB loader


class NaiveCollection:
    """Lightweight loader for plaintext vectors and metadata."""

    def __init__(self, collection_dir: Path):
        self.dir = collection_dir
        with (self.dir / "meta.json").open("r", encoding="utf-8") as f:
            self.meta: Dict = json.load(f)

        data = np.load(self.dir / "vector.npz", allow_pickle=True)
        self.vectors: np.ndarray = data["vector"]
        self.ids: np.ndarray = data["id"]
        self.dimension = self.meta["dimension"]
        self.metric_type = self.meta["metric_type"]

    def get_all_scores(self, query_vec: np.ndarray) -> np.ndarray:
        """Computes IP scores against all vectors in the collection."""
        return self.vectors @ query_vec.T


# -------------------------------------------------- Evaluation Logic


def load_qa_data(path: Path) -> List[dict]:
    print(f"Loading QA data from {path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"Loaded {len(data)} QA pairs")
    return data


def setup_HEVEC_collections(
    client: hevec_py.HEVECClient, memory_db_root: Path
) -> Dict[str, NaiveCollection]:
    """Sets up collections on the HEVEC server and returns loaded plaintext data."""
    print("\nSetting up HEVEC collections...")
    collections: Dict[str, NaiveCollection] = {}
    collection_dirs = [p for p in memory_db_root.iterdir() if p.is_dir()]

    for i, collection_dir in enumerate(collection_dirs):
        collection_name = collection_dir.name
        print(f"  [{i+1}/{len(collection_dirs)}] Processing {collection_name}...")

        # Load plaintext data
        collection = NaiveCollection(collection_dir)
        collections[collection_name] = collection

        # Drop and set up on HEVEC server
        try:
            client.drop_collection(collection_name)
        except Exception:
            # It's okay if the collection doesn't exist
            pass
        client.setup_collection(collection_name, collection.dimension, collection.metric_type, is_query_encrypt=IS_QUERY_ENCRYPT)

        # Insert vectors to HEVEC server in batches
        vectors_to_insert = collection.vectors
        for j in range(0, len(vectors_to_insert), 4096):
            end_idx = min(j + 4096, len(vectors_to_insert))
            batch = vectors_to_insert[j:end_idx]
            payloads = [f"doc_{k}" for k in range(j, end_idx)]
            client.insert(collection_name, batch, payloads)
    print("HEVEC setup complete.")
    return collections


def evaluate(
    qa_data: List[dict],
    local_collections: Dict[str, NaiveCollection],
    client: hevec_py.HEVECClient,
    encoder: DragonQueryEncoder,
    top_k: int = 10,
) -> None:
    recall1 = recall5 = recall10 = 0
    mrr = 0.0
    processed = 0
    all_errors: List[float] = []

    print("\nStarting evaluation...")
    for qa in qa_data:
        question = qa["question"]
        user_ids = qa.get("related_user_ids", [])
        if not user_ids:
            continue
        collection_name = user_ids[0]

        if collection_name not in local_collections:
            continue

        collection = local_collections[collection_name]
        query_vec = encoder([question])[0]

        # Get encrypted scores from HEVEC
        predicted_scores = np.array(client.query(collection_name, query_vec))

        # Calculate ground truth scores locally
        gt_scores = collection.get_all_scores(query_vec)

        # Ensure lengths match before calculating error
        min_len = min(len(predicted_scores), len(gt_scores))
        errors = np.abs(predicted_scores[:min_len] - gt_scores[:min_len])
        all_errors.extend(errors)

        # Get top-k indices
        gt_top_k_indices = np.argsort(gt_scores)[-top_k:][::-1]
        gt_max_idx = gt_top_k_indices[0]

        encrypted_top_k_indices = np.argsort(predicted_scores)[-top_k:][::-1]

        # Calculate recall and MRR
        for rank, idx in enumerate(encrypted_top_k_indices, 1):
            if idx == gt_max_idx:
                if rank == 1:
                    recall1 += 1
                if rank <= 5:
                    recall5 += 1
                if rank <= 10:
                    recall10 += 1
                mrr += 1.0 / rank
                break

        processed += 1
        if processed % 50 == 0:
            print(f"  Processed {processed} / {len(qa_data)} questions…")

    if processed == 0:
        print("No examples processed, check data & paths.")
        return

    # --- Summary
    print("\n===== Evaluation Result =====")
    print(f"Examples processed      : {processed}")
    print("\n--- Score Error (HEVEC vs. Plaintext) ---")
    if all_errors:
        print(f"  - Max Error    : {np.max(all_errors):.2e}")
        print(f"  - Mean Error   : {np.mean(all_errors):.2e}")
        print(f"  - Std Dev Error: {np.std(all_errors):.2e}")
    else:
        print("  - No scores found to compare.")

    print("\n--- Ranking Accuracy ---")
    print(f"  - Recall@1  : {recall1 / processed:.4f}")
    print(f"  - Recall@5  : {recall5 / processed:.4f}")
    print(f"  - Recall@10 : {recall10 / processed:.4f}")
    print(f"  - MRR       : {mrr / processed:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser("HEVEC Precision Evaluation (stand-alone)")
    parser.add_argument(
        "--qa_json",
        type=str,
        default=".db/locomo/base/json_data/qa.json",
        help="Path to qa.json",
    )
    parser.add_argument(
        "--memory_db_root",
        type=str,
        default=".db/locomo/base/dense/memory_dragon_naive.db",
        help="Directory containing per-user plaintext vector collections",
    )
    parser.add_argument("--top_k", type=int, default=10, help="Top-K for retrieval")
    parser.add_argument("--HEVEC_host", type=str, default="localhost", help="HEVEC server host")
    parser.add_argument("--HEVEC_port", type=str, default="9000", help="HEVEC server port")
    args = parser.parse_args()

    client = hevec_py.HEVECClient(args.HEVEC_host, args.HEVEC_port)
    try:
        local_collections = setup_HEVEC_collections(client, Path(args.memory_db_root))
        qa_data = load_qa_data(Path(args.qa_json))
        encoder = DragonQueryEncoder()
        evaluate(qa_data, local_collections, client, encoder, top_k=args.top_k)
    finally:
        print("\nTerminating HEVEC client.")
        client.terminate()


if __name__ == "__main__":
    main() 
