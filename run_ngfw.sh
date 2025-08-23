#!/bin/bash

# Script pour lancer le Dashboard ET le NGFW en parallèle
# Auteur: Samuel Biraheka
# Projet: NGFW-Congo

echo " Démarrage de NGFW-Congo en mode temps réel..."
echo "Dashboard: http://192.168.178.39:5000"
echo "----------------------------------------"

# Se placer dans le dossier du projet
cd /home/biraheka/ngfw/my_tfc_ngfw

# Fonction pour nettoyer les processus à la fin
cleanup() {
    echo ""
    echo " Arrêt de NGFW-Congo..."
    kill $DASH_PID $NGFW_PID 2>/dev/null
    exit 0
}

# Capturer le signal Ctrl+C pour arrêter proprement
trap cleanup INT TERM

# 1. LANCER LE DASHBOARD EN ARRIÈRE-PLAN
echo " Lancement du Dashboard Flask..."
python app/dashboard/app.py &
DASH_PID=$!
sleep 3  # Donner un peu de temps au dashboard pour démarrer

# 2. LANCER LE NGFW EN BOUCLE
echo " Lancement du NGFW en mode surveillance continue..."
echo "Appuyez sur Ctrl+C pour arrêter"
echo "----------------------------------------"

while true; do
    echo "=== Nouvelle capture démarrée ==="
    python main.py
    sleep 10  # Attend 10 secondes avant la prochaine capture
done &
NGFW_PID=$!

# Attendre que l'utilisateur appuie sur Ctrl+C
wait