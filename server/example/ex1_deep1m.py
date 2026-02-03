import sys
import numpy as np
import struct
from typing import Tuple

import hevec_py

DEGREE = 4096

N_DB = 1000000
N_QUERY = 10000
IS_QUERY_ENCRYPT = False

def load_fbin(filepath: str) -> Tuple[np.ndarray, int, int]:
    """
    fbin format: [n_vectors(4bytes)][dimension(4bytes)][vector_data...]
    Returns: (data, n_vectors, dimension)
    """
    print(f"Loading fbin file: {filepath}")
    
    with open(filepath, 'rb') as f:
        # Read header: [num_vectors, vector_dim, vector_array]
        n = struct.unpack('<I', f.read(4))[0]  # number of vectors
        d = struct.unpack('<I', f.read(4))[0]  # dimension
        print(f"Header: {n} vectors of dimension {d}")
        data = np.fromfile(f, dtype=np.float32, count=n * d)
        data = data.reshape(n, d)
    
    print(f"Successfully loaded fbin: shape {data.shape}")
    return data, n, d

def main():
    if len(sys.argv) != 3:
        print("Usage: python ex0_deep1m.py <base_vectors> <query_vectors>")
        print("Example: python ex0_deep1m.py deep1M_base.fbin deep1M_query.fbin")
        sys.exit(1)

    base_path = sys.argv[1]
    query_path = sys.argv[2]

    # Load base and query vectors
    B, _, d_base = load_fbin(base_path)
    Q, _, d_query = load_fbin(query_path)
    
    if d_base != d_query:
        raise ValueError(f"Dimension mismatch: base={d_base}, query={d_query}")
    
    B = B[:N_DB]
    Q = Q[:N_QUERY]

    # Connect to the HEVEC server
    client = hevec_py.HEVECClient("localhost", "9000")
    
    try:
        # Setup a new collection
        collection_name = "deep1m_collection"
        dimension = B.shape[1]
        metric_type = "COSINE"
        
        # Cleanup from previous runs
        try:
            client.drop_collection(collection_name)
        except Exception as e:
            # It's okay if the collection doesn't exist
            pass
        
        client.setup_collection(collection_name, dimension, metric_type)

        # Insert data in batches
        print("Inserting database vectors...")
        for i in range(0, len(B), DEGREE):
            end_idx = min(i + DEGREE, len(B))
            batch_vectors = B[i:end_idx]
            batch_payloads = [f"doc_{j}" for j in range(i, end_idx)]
            
            client.insert(collection_name, batch_vectors, batch_payloads)
            if (i // DEGREE) % 10 == 0:
                print(f"  -> Inserted {end_idx}/{len(B)} vectors")

        print("Starting encrypted queries...")
        
        all_errors = []
        recall1 = 0.0
        recall5 = 0.0
        recall10 = 0.0
        mrr = 0.0

        k = 10

        for i in range(min(N_QUERY, len(Q))):
            if i > 0 and i % 100 == 0:
                print(f"  -> Processed {i}/{min(N_QUERY, len(Q))} queries")
            
            query_vec = Q[i]
            
            # Get encrypted scores from HEVEC
            all_scores = client.query(collection_name, query_vec)
            
            # Compute ground truth scores locally
            query_norm = query_vec / np.linalg.norm(query_vec)
            B_norm = B / np.linalg.norm(B, axis=1, keepdims=True)
            gt_scores = np.dot(B_norm, query_norm)

            # Measure error
            for j in range(min(len(all_scores), len(gt_scores))):
                error = abs(gt_scores[j] - all_scores[j])
                all_errors.append(error)
            
            # Get top-k indices from ground truth and encrypted results
            gt_top_k_indices = np.argsort(gt_scores)[-k:][::-1]
            gt_max_idx = gt_top_k_indices[0]
            
            encrypted_top_k_indices = np.argsort(all_scores)[-k:][::-1]
            
            # Calculate recall and MRR
            for j, idx in enumerate(encrypted_top_k_indices):
                if idx == gt_max_idx:
                    if j == 0:
                        recall1 += 1
                    if j < 5:
                        recall5 += 1
                    if j < 10:
                        recall10 += 1
                    mrr += 1.0 / (j + 1)
                    break

        n_queries_processed = min(N_QUERY, len(Q))
        
        print(f"\nResults after {n_queries_processed} queries:")
        print(f"  - Max error : {np.max(all_errors):.2e}")
        print(f"  - Mean error: {np.mean(all_errors):.2e}")
        print(f"  - Std error : {np.std(all_errors):.2e}")
        print(f"  - MRR       : {mrr / n_queries_processed:.4f}")
        print(f"  - Recall@1  : {recall1 / n_queries_processed:.4f}")
        print(f"  - Recall@5  : {recall5 / n_queries_processed:.4f}")
        print(f"  - Recall@10 : {recall10 / n_queries_processed:.4f}")

    finally:
        client.terminate()

if __name__ == "__main__":
    main() 
