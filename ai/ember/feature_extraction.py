from .features import PEFeatureExtractor
import os
from multiprocessing import Pool
from tqdm import tqdm
import pickle
import json
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)


def extract_raw_features(args):
    """
    Extract features from a malware file using the PEFeatureExtractor.
    Args:
        args (tuple): Tuple containing the PEFeatureExtractor instance and the malware filename.
    Returns:
        dict: Extracted features.
    """
    extractor, malware_filename = args
    with open(malware_filename, "rb") as f:
        f_bytes = f.read()
    return extractor.raw_features(f_bytes)


def convert_bytes(obj):
    """
    Convert bytes to string for JSON serialization.
    Args:
        obj (bytes): Bytes object to convert.
    Returns:
        str: Converted string.
    Raises:
        TypeError: If the object is not bytes.
    """
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    raise TypeError(f"Type {type(obj)} not serializable")


def create_ember_dataset():
    """
    Create the EMBER dataset by extracting features from malware files.
    """

    extractor = PEFeatureExtractor()

    base_dir = os.environ.get(
        "MALWARE_DIR_PATH"
    )  # "/home/luca/WD/NortonDataset670/MALWARE"
    if base_dir is None:
        base_dir = "/home/luca/WD/NortonDataset670/MALWARE"
    malware_families_dirs = os.listdir(base_dir)

    malware_filenames = []
    malware_families = []
    for malware_family_dir in malware_families_dirs:
        malware_family_abs_dir = os.path.join(base_dir, malware_family_dir)
        for malware_filename in os.listdir(malware_family_abs_dir):
            malware_families.append(malware_family_dir)
            malware_filenames.append(
                os.path.join(malware_family_abs_dir, malware_filename)
            )

    logger.info(
        f"Detected {len(malware_filenames)} malware files and, {len(malware_families_dirs)} families"
    )

    # Extract features
    logger.info("Starting feature extraction...")
    n_proc = os.environ.get("N_PROCESSES")
    if n_proc is None:
        n_proc = 32
    else:
        n_proc = int(n_proc)
    with Pool(n_proc) as p:
        malware_ember_features = list(
            tqdm(
                p.imap(
                    extract_raw_features,
                    [(extractor, filename) for filename in malware_filenames],
                ),
                total=len(malware_filenames),
            )
        )

    logger.info("Feature extraction completed.")
    logger.info("Starting feature merging...")
    features = []
    for malware_features in tqdm(malware_ember_features, desc="Merging features"):
        features.append(extractor.process_raw_features(malware_features))

    # Extract SHA256 to use them as DataFrame index
    shas_256 = [
        malware_features["sha256"] for malware_features in malware_ember_features
    ]
    # Create the dataframe with column names of the full dataset (train + test)
    df = pd.DataFrame(features, index=shas_256, columns=extractor.column_names())
    df["family"] = malware_families

    logger.info("Feature merging completed.")

    # Save the dataframe to a CSV file
    final_dataset_path = os.environ.get("FINAL_DATASET_DIR")
    if final_dataset_path is None:
        final_dataset_path = "dataset"

    malware_dataset_filename = os.path.join(
        final_dataset_path, "malware_ember_features.csv"
    )
    df.to_csv(malware_dataset_filename, index=True, index_label="sha256")
    logger.info(f"Dataframe of shape {df.shape} saved to {malware_dataset_filename}")
    logger.info("Done.")


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    # Create the EMBER dataset
    create_ember_dataset()
