# entrainement.py
"""
Script d'entraînement du modèle de détection d'anomalies (Isolation Forest).
Charge les données depuis le dataset CIC-IDS2017, les prépare, entraîne le modèle et le sauvegarde.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import os
import logging
from pathlib import Path

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration des chemins
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data" / "raw_data"
MODEL_DIR = BASE_DIR / "data" / "models"
MODEL_PATH = MODEL_DIR / "isolation_forest_model.pkl"
SCALER_PATH = MODEL_DIR / "standard_scaler.pkl"

def load_and_preprocess_data(file_path: Path) -> pd.DataFrame:
    """
    Charge et prépare le dataset pour l'entraînement.
    Args:
        file_path (Path): Chemin vers le fichier CSV du dataset.
    Returns:
        pd.DataFrame: DataFrame Pandas nettoyé et préparé.
    """
    logger.info(f"Chargement des données depuis : {file_path}")
    
    # Lecture du CSV. Les datasets CIC-IDS2017 utilisent ';' comme séparateur.
    df = pd.read_csv(file_path, sep=',', encoding='utf-8')
    logger.info(f"Données brutes chargées. Shape: {df.shape}")

    # 1. Nettoyage basique
    # Suppression des colonnes inutiles ou avec trop de NaN
    cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'SimillarHTTP']
    # Ne garder que les colonnes qui existent dans le DataFrame
    cols_to_drop = [col for col in cols_to_drop if col in df.columns]
    df.drop(columns=cols_to_drop, inplace=True, errors='ignore')

    # Suppression des lignes avec des valeurs NaN
    df.dropna(inplace=True)
    logger.info(f"Après suppression des NaN. Shape: {df.shape}")

    # 2. Nettoyage des valeurs infinies et aberrantes
    logger.info("Nettoyage des valeurs infinies et aberrantes...")
    # Remplacer les infinis par NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Supprimer les lignes avec des NaN (causées par les infinis)
    df.dropna(inplace=True)
    
    # Gestion des valeurs aberrantes : optionnel mais recommandé
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        # Créer un masque pour les valeurs dans une plage raisonnable
        mask = (df[col] < 1e9) & (df[col] > -1e9)
        df = df.loc[mask]

    logger.info(f"Après nettoyage des valeurs infinies/aberrantes. Shape: {df.shape}")

    # 3. Gestion des labels (si la colonne 'Label' existe)
    if 'Label' in df.columns:
        logger.info("Filtrage pour ne garder que le trafic 'BENIGN'...")
        df = df[df['Label'] == 'BENIGN']
        df.drop(columns=['Label'], inplace=True)
        logger.info(f"Après filtrage du trafic normal. Shape: {df.shape}")

    # --- NOUVEAU POUR LE MVP : SELECTION DE 1-2 FEATURES SIMPLES ---
    logger.info("Sélection des features pour le modèle MVP...")
    # CHOISISSEZ UNE SEULE FEATURE TRÈS SIMPLE ET DISPONIBLE
    # 'Total Length of Fwd Packets' est un bon choix (c'est ~ la taille des paquets envoyés)
    feature_a_garder = ['Total Length of Fwd Packets']  # Une seule feature !
    
    # S'assurer que la feature existe
    if feature_a_garder[0] not in df.columns:
        feature_a_garder = [df.select_dtypes(include=[np.number]).columns[0]]
        logger.warning(f"Feature non trouvée. Utilisation de '{feature_a_garder[0]}' comme fallback.")
    
    # Ne garder que la feature choisie pour l'entraînement MVP
    df = df[feature_a_garder]
    logger.info(f"Feature sélectionnée pour le MVP: {feature_a_garder}")
    logger.info(f"Shape final pour l'entraînement MVP: {df.shape}")
    # 4. Encodage des features catégorielles (ex: 'Protocol')
    label_encoders = {}
    for column in df.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        df[column] = le.fit_transform(df[column].astype(str))
        label_encoders[column] = le
        logger.debug(f"Colonne encodée: {column}")

    return df


def train_model(df: pd.DataFrame):
    """
    Entraîne un modèle Isolation Forest sur les données fournies.
    Args:
        df (pd.DataFrame): DataFrame préparé pour l'entraînement.
    Returns:
        tuple: (model, scaler) Le modèle entraîné et le scaler utilisé.
    """
    logger.info("Début de l'entraînement du modèle...")

    # Séparation des features (X)
    X = df.values

    # Normalisation des features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    logger.info("Normalisation des features terminée.")

    # Entraînement du modèle Isolation Forest
    # Contamination : fraction attendue des anomalies. Mettre une valeur faible (0.01 -> 1%) pour du trafic normal.
    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=0.01,
        random_state=42,
        n_jobs=-1 # Utilise tous les coeurs du CPU
    )
    model.fit(X_scaled)
    logger.info("Entraînement du modèle Isolation Forest terminé.")

    return model, scaler

def main():
    """Fonction principale du script d'entraînement."""
    # Assurer l'existence des dossiers
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # --- ÉTAPE 1 : Trouver le fichier de données ---
    # Cherche n'importe quel fichier CSV dans le dossier raw_data
    data_files = list(DATA_DIR.glob("*.csv"))
    if not data_files:
        error_msg = f"Aucun fichier CSV trouvé dans {DATA_DIR}. Veuillez y placer un fichier du dataset CIC-IDS2017."
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)

    # Prend le premier fichier CSV trouvé
    data_file = data_files[0]
    logger.info(f"Utilisation du fichier de données: {data_file.name}")

    try:
        # --- ÉTAPE 2 : Chargement et Préprocessing ---
        df_processed = load_and_preprocess_data(data_file)

        # Pour le MVP, limitons-nous à 50 000 lignes pour aller vite
        if len(df_processed) > 50000:
            df_processed = df_processed.sample(n=50000, random_state=42)
            logger.info(f"Échantillonnage à 50 000 lignes pour l'entraînement MVP.")

        # --- ÉTAPE 3 : Entraînement ---
        model, scaler = train_model(df_processed)

        # --- ÉTAPE 4 : Sauvegarde ---
        joblib.dump(model, MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        logger.info(f"Modèle sauvegardé avec succès dans : {MODEL_PATH}")
        logger.info(f"Scaler sauvegardé avec succès dans : {SCALER_PATH}")

    except Exception as e:
        logger.error(f"Une erreur s'est produite lors de l'entraînement: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
