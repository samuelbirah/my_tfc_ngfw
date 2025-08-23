# app/core/detector.py
"""
Module de détection d'anomalies utilisant un modèle Isolation Forest pré-entraîné.
Charge le modèle et le scaler sauvegardés pour noter le trafic capturé.
"""
import joblib
import pandas as pd
import numpy as np
import logging
from pathlib import Path

# Configuration du logging
logger = logging.getLogger(__name__)

class DetecteurAnomalies:
    """
    Classe responsable de la détection d'anomalies dans les métadonnées du trafic réseau.
    Attributes:
        model: Modèle Isolation Forest entraîné.
        scaler: Scaler StandardScaler entraîné.
    """

    def __init__(self, model_path: Path, scaler_path: Path):
        """
        Initialise le détecteur en chargeant le modèle et le scaler depuis les fichiers.
        Args:
            model_path (Path): Chemin vers le fichier .pkl du modèle.
            scaler_path (Path): Chemin vers le fichier .pkl du scaler.
        Raises:
            FileNotFoundError: Si les fichiers de modèle ou de scaler sont introuvables.
        """
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            logger.info(f"Modèle et scaler chargés depuis {model_path} et {scaler_path}")
        except FileNotFoundError as e:
            logger.critical(f"Fichier de modèle ou de scaler introuvable : {e}")
            raise
        except Exception as e:
            logger.critical(f"Erreur lors du chargement du modèle/scaler : {e}")
            raise

    def preparer_features(self, df_capture: pd.DataFrame) -> np.ndarray:
        """
        Prépare les features du DataFrame de capture pour la prédiction.
        NOTE: Utilise la MÊME feature que celle utilisée pour l'entraînement du modèle MVP.
        """
        logger.debug("Préparation des features pour la prédiction...")
        
        # ICI : Utilisez la feature que vous avez choisie dans entrainement.py
        # Le script d'entraînement a loggué : "Feature sélectionnée pour le MVP: ['Total Length of Fwd Packets']"
        feature_name = 'Total Length of Fwd Packets'  # <--- REMPLACEZ 'length' PAR CECI

        # Pour l'instant, nous approximons 'Total Length of Fwd Packets' par la longueur du paquet capturé ('length').
        # C'est une approximation valable pour le MVP.
        # Créez un DataFrame avec une colonne du même nom que celle utilisée à l'entraînement.
        X_pred = df_capture[['length']].copy()
        X_pred = X_pred.rename(columns={'length': feature_name})  # Renommez la colonne
        
        # Application de la même normalisation que pendant l'entraînement
        X_scaled = self.scaler.transform(X_pred)
        return X_scaled

    def analyser(self, df_capture: pd.DataFrame) -> pd.DataFrame:
        """
        Analyse le trafic capturé et retourne les résultats avec les scores d'anomalie.
        Args:
            df_capture (pd.DataFrame): DataFrame des paquets capturés par le module Capturer.
        Returns:
            pd.DataFrame: DataFrame original enrichi des colonnes 'anomaly_score' et 'is_anomaly'.
        """
        if df_capture.empty:
            logger.warning("Le DataFrame de capture est vide. Aucune analyse effectuée.")
            return df_capture

        try:
            # Préparation des features
            features = self.preparer_features(df_capture)
            
            # Prédiction avec le modèle Isolation Forest
            # Le modèle retourne -1 pour les anomalies, 1 pour le normal.
            predictions = self.model.predict(features)
            
            # Les decision_function donne le score de normalité (négatif = plus anomal)
            # Plus le score est bas, plus l'échantillon est anormal.
            scores = self.model.decision_function(features)
            
            # Ajout des résultats au DataFrame
            df_result = df_capture.copy()
            df_result['anomaly_score'] = scores
            df_result['is_anomaly'] = (predictions == -1)
            
            logger.info(f"Analyse terminée. {df_result['is_anomaly'].sum()} anomalies détectées sur {len(df_result)} paquets.")
            return df_result

        except Exception as e:
            logger.error(f"Erreur lors de l'analyse : {e}", exc_info=True)
            raise

# Exemple d'utilisation et test basique
if __name__ == "__main__":
    from pathlib import Path
    import logging
    logging.basicConfig(level=logging.INFO)
    
    BASE_DIR = Path(__file__).parent.parent.parent
    MODEL_PATH = BASE_DIR / "data" / "models" / "isolation_forest_model.pkl"
    SCALER_PATH = BASE_DIR / "data" / "models" / "standard_scaler.pkl"
    
    # Test du module
    print("Test du module DetecteurAnomalies...")
    try:
        # 1. Créer des données de test factices
        data_test = {
            'timestamp': ['2023-01-01T00:00:00', '2023-01-01T00:00:01'],
            'src_ip': ['192.168.1.1', '10.0.0.1'],
            'dst_ip': ['8.8.8.8', '192.168.1.2'],
            'protocol': [6, 6],
            'length': [60, 1500]  # Une taille normale et une grande taille (potentiellement anomalie)
        }
        df_test = pd.DataFrame(data_test)
        
        # 2. Charger le détecteur
        detecteur = DetecteurAnomalies(MODEL_PATH, SCALER_PATH)
        
        # 3. Analyser les données de test
        results = detecteur.analyser(df_test)
        
        print("Test réussi. Résultats de l'analyse :")
        print(results[['timestamp', 'src_ip', 'dst_ip', 'length', 'anomaly_score', 'is_anomaly']])
        
    except Exception as e:
        print(f"Échec du test: {e}")
