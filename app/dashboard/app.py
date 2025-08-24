# app/dashboard/app.py
from flask import Flask, render_template, jsonify
import pandas as pd
from pathlib import Path
import logging

app = Flask(__name__, template_folder='templates')  # <-- Ajoutez template_folder='templates'
LOG_FILE = Path(__file__).parent.parent.parent / "logs" / "derniere_analyse.csv"

@app.route('/')
def index():
    """Page principale du dashboard."""
    return render_template('index.html')

@app.route('/api/alertes')
def get_alertes():
    """API pour récupérer les alertes du dernier scan."""
    try:
        if LOG_FILE.exists():
            df = pd.read_csv(LOG_FILE)
            # Convertir la colonne 'is_anomaly' en booléen (elle est lue comme string depuis CSV)
            df['is_anomaly'] = df['is_anomaly'].astype(bool)
            alertes = df[df['is_anomaly'] == True].to_dict('records')
            return jsonify(alertes)
        return jsonify([])
    except Exception as e:
        logging.error(f"Erreur API: {e}")
        return jsonify([])

# Ajoutez cette nouvelle route
@app.route('/api/derniere-analyse')
def get_derniere_analyse():
    """API pour récupérer TOUTES les données de la dernière analyse."""
    try:
        if LOG_FILE.exists():
            df = pd.read_csv(LOG_FILE)
            # Convertir la colonne 'is_anomaly' en booléen
            df['is_anomaly'] = df['is_anomaly'].astype(bool)
            
            alertes = df[df['is_anomaly'] == True].to_dict('records')
            total_paquets = len(df)
            
            return jsonify({
                'total_paquets': total_paquets,
                'alertes': alertes,
                'timestamp_analyse': df['timestamp'].iloc[0] if not df.empty else None
            })
        return jsonify({'total_paquets': 0, 'alertes': []})
    except Exception as e:
        logging.error(f"Erreur API dernière-analyse: {e}")
        return jsonify({'total_paquets': 0, 'alertes': []})

# Gardez l'ancienne API pour la compatibilité
@app.route('/api/alertes')
def get_alertes():
    """API pour récupérer seulement les alertes."""
    try:
        if LOG_FILE.exists():
            df = pd.read_csv(LOG_FILE)
            df['is_anomaly'] = df['is_anomaly'].astype(bool)
            alertes = df[df['is_anomaly'] == True].to_dict('records')
            return jsonify(alertes)
        return jsonify([])
    except Exception as e:
        logging.error(f"Erreur API alertes: {e}")
        return jsonify([])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)