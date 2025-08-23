# main.py
"""
Point d'entrée principal de l'application NGFW-Congo.
Orchestre la capture du trafic et son analyse par le modèle IA.
"""
import logging
from pathlib import Path
import pandas as pd

# Importation de nos modules
from app.core.capturer import Capturer
from app.core.detector import DetecteurAnomalies

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/ngfw_congo.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """Fonction principale orchestrant la capture et l'analyse."""
    logger.info("=== Démarrage de NGFW-Congo MVP ===")
    
    # Configuration des chemins
    BASE_DIR = Path(__file__).parent
    MODEL_PATH = BASE_DIR / "data" / "models" / "isolation_forest_model.pkl"
    SCALER_PATH = BASE_DIR / "data" / "models" / "standard_scaler.pkl"
    
    try:
        # 1. Initialisation des modules
        logger.info("Initialisation des modules...")
        capturer = Capturer(interface="enp0s3")  # Utilisez votre interface
        detecteur = DetecteurAnomalies(MODEL_PATH, SCALER_PATH)
        
        # 2. Capture du trafic réseau
        logger.info("Lancement de la capture réseau...")
        df_traffic = capturer.start_capture(count=50)  # Capture 50 paquets
        
        if df_traffic.empty:
            logger.warning("Aucun paquet capturé. Vérifiez l'interface réseau.")
            return
        
        # 3. Analyse IA du trafic capturé
        logger.info("Analyse du trafic par l'IA...")
        results_df = detecteur.analyser(df_traffic)
        
        # 4. Affichage des résultats
        logger.info("=== RÉSULTATS DE L'ANALYSE ===")
        logger.info(f"Paquets analysés: {len(results_df)}")
        
        # Filtrer et afficher seulement les anomalies
        anomalies_df = results_df[results_df['is_anomaly'] == True]
        logger.info(f"Anomalies détectées: {len(anomalies_df)}")
        
        if not anomalies_df.empty:
            logger.warning("⚠️  ANOMALIES DÉTECTÉES !")
            for index, row in anomalies_df.iterrows():
                logger.warning(f"ANOMALIE - IP Source: {row['src_ip']} -> IP Dest: {row['dst_ip']} | Taille: {row['length']} | Score: {row['anomaly_score']:.4f}")
        else:
            logger.info("✅ Aucune anomalie détectée. Trafic normal.")
            
        # Sauvegarde des résultats pour inspection (optionnel)
        results_csv_path = BASE_DIR / "logs" / "derniere_analyse.csv"
        results_df.to_csv(results_csv_path, index=False)
        logger.info(f"Résultats détaillés sauvegardés dans: {results_csv_path}")
        
    except Exception as e:
        logger.critical(f"Erreur critique dans le flux principal: {e}", exc_info=True)
    finally:
        logger.info("=== Arrêt de NGFW-Congo MVP ===")

if __name__ == "__main__":
    main()
