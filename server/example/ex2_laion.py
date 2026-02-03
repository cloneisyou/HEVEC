import sys
import numpy as np

import hevec_py

DEGREE = 4096

N_DB = 100000
N_QUERY = 1000
IS_QUERY_ENCRYPT = False

def main():
    if len(sys.argv) != 3:
        print("Usage: python ex7_laion.py <img_emb_path> <text_emb_path>")
        print("Example: python ex7_laion.py .db/laion-400m/img_emb_0.npy .db/laion-400m/text_emb_0.npy")
        sys.exit(1)

    img_emb_path = sys.argv[1]
    text_emb_path = sys.argv[2]

    # Load image and text embeddings
    B = np.load(img_emb_path).astype(np.float32)
    Q = np.load(text_emb_path).astype(np.float32)

    B = B[:N_DB]
    Q = Q[:N_QUERY]

    # Connect to the HEVEC server
    client = hevec_py.HEVECClient("localhost", "9000")
    
    try:
        # Setup a new collection
        collection_name = "laion_collection"
        dimension = B.shape[1]
        metric_type = "COSINE"
        
        # Cleanup from previous runs
        try:
            client.drop_collection(collection_name)
        except Exception as e:
            # It's okay if the collection doesn't exist
            pass
        
        client.setup_collection(collection_name, dimension, metric_type, IS_QUERY_ENCRYPT)

        # Insert data in batches
        print("Inserting database vectors...")
        for i in range(0, N_DB, DEGREE):
            end_idx = min(i + DEGREE, N_DB)
            batch_vectors = B[i:end_idx]
            batch_payloads = [f"doc_{j}" for j in range(i, end_idx)]
            
            client.insert(collection_name, batch_vectors, batch_payloads)
            if (i // DEGREE) % 10 == 0:
                print(f"  -> Inserted {end_idx}/{N_DB} vectors")

        print("Starting encrypted queries...")
        
        all_errors = []
        recall1 = 0.0
        recall5 = 0.0
        mrr = 0.0

        k = 10

        for i in range(N_QUERY):
            if i > 0 and i % 100 == 0:
                print(f"  -> Processed {i}/{N_QUERY} queries")
            
            query_vec = Q[i]
            
            # Get encrypted scores from HEVEC
            all_scores = client.query(collection_name, query_vec)
            
            # Compute ground truth scores locally
            gt_scores = np.dot(B, query_vec)

            # Measure error
            for j in range(len(all_scores)):
                if j < N_DB:
                    error = abs(gt_scores[j] - all_scores[j])
                    all_errors.append(error)
            
            # Get top-k indices
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
                    mrr += 1.0 / (j + 1)
                    break

        print(f"\nResults after {N_QUERY} queries:")
        print(f"  - Max error : {np.max(all_errors):.2e}")
        print(f"  - Mean error: {np.mean(all_errors):.2e}")
        print(f"  - Std error : {np.std(all_errors):.2e}")
        print(f"  - MRR       : {mrr / N_QUERY:.4f}")
        print(f"  - Recall@1  : {recall1 / N_QUERY:.4f}")
        print(f"  - Recall@5  : {recall5 / N_QUERY:.4f}")

    finally:
        client.terminate()

if __name__ == "__main__":
    main() 
