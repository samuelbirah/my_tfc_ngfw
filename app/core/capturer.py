# app/core/capturer.py
"""
Module de capture du trafic réseau utilisant Scapy.
Gère la capture passive des paquets et leur stockage temporaire dans un DataFrame.
"""
from scapy.all import sniff, IP, TCP, UDP
from scapy.interfaces import get_working_ifaces
import pandas as pd
from datetime import datetime
import logging

# Configuration du logging pour ce module
logger = logging.getLogger(__name__)

class Capturer:
    """
    Classe responsable de la capture des paquets réseau sur une interface spécifiée.
    Attributes:
        interface (str): Nom de l'interface réseau à écouter (ex: 'enp0s3', 'wlo1').
        packets_data (list): Liste temporaire pour stocker les métadonnées des paquets capturés.
    """

    def __init__(self, interface: str = None):
        """
        Initialise le capteur.
        Si aucune interface n'est spécifiée, tente de trouver une interface par défaut.
        Args:
            interface (str, optional): Nom de l'interface. Defaults to None.
        Raises:
            ValueError: Si l'interface spécifiée n'existe pas ou si aucune interface n'est trouvée.
        """
        self.interface = self._validate_interface(interface)
        self.packets_data = []
        logger.info(f"Capturer initialisé sur l'interface: {self.interface}")

    def _validate_interface(self, interface: str) -> str:
        """
        Valide le nom de l'interface réseau ou en trouve une par défaut.
        Returns:
            str: Le nom d'une interface réseau valide.
        Raises:
            ValueError: Si aucune interface valide n'est trouvée.
        """
        available_ifaces = [iface.name for iface in get_working_ifaces()]
        
        if interface and interface in available_ifaces:
            return interface
        elif available_ifaces:
            # Retourne la première interface disponible si aucune n'est spécifiée
            logger.warning(f"Interface '{interface}' non trouvée. Utilisation de '{available_ifaces[0]}' par défaut.")
            return available_ifaces[1]
        else:
            error_msg = "Aucune interface réseau disponible n'a été trouvée."
            logger.error(error_msg)
            raise ValueError(error_msg)

    def _packet_handler(self, packet) -> None:
        """
        Callback appelé par Scapy pour chaque paquet capturé.
        Extrait les métadonnées basiques et les stocke.
        Args:
            packet: Paquet réseau capturé par Scapy.
        """
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                metadata = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'length': len(packet)
                }
                self.packets_data.append(metadata)
                logger.debug(f"Paquet capturé: {metadata['src_ip']} -> {metadata['dst_ip']}")

        except Exception as e:
            logger.error(f"Erreur lors du traitement du paquet: {e}", exc_info=True)

    def start_capture(self, count: int = 100) -> pd.DataFrame:
        """
        Démarre une capture réseau pour un nombre défini de paquets.
        Args:
            count (int, optional): Nombre de paquets à capturer. Defaults to 100.
        Returns:
            pd.DataFrame: DataFrame Pandas contenant les métadonnées des paquets capturés.
        """
        logger.info(f"Démarrage de la capture de {count} paquets...")
        self.packets_data.clear()  # Nettoie les données des captures précédentes

        try:
            sniff(iface=self.interface, prn=self._packet_handler, count=count, store=False)
            df = pd.DataFrame(self.packets_data)
            logger.info(f"Capture terminée. {len(df)} paquets capturés.")
            return df

        except PermissionError:
            error_msg = f"Permissions insuffisantes pour capturer sur {self.interface}. Exécutez avec sudo/Admin."
            logger.critical(error_msg)
            raise PermissionError(error_msg)
        except Exception as e:
            logger.critical(f"Erreur critique lors de la capture: {e}", exc_info=True)
            raise

# Exemple d'utilisation et test basique
if __name__ == "__main__":
    # Configuration basique du logging pour voir les messages dans la console
    logging.basicConfig(level=logging.INFO)
    
    # Test du module
    print("Test du module Capturer...")
    try:
        capturer = Capturer()
        df = capturer.start_capture(count=5)  # Capture seulement 5 paquets pour le test
        print("Capture réussie. Aperçu des données :")
        print(df.head())
    except Exception as e:
        print(f"Échec du test: {e}")
