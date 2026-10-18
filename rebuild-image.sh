#!/bin/sh
# ============================================================
#  SimCity — Reconstruction périodique des images (correctifs de sécurité)
#
#  L'image php:8.3-apache-trixie n'est republiée que de temps en temps, et
#  un « docker build » ordinaire réutilise le cache : sans reconstruction
#  complète, OpenSSL, libxml, libldap, pdftotext… ne reçoivent jamais leurs
#  correctifs Debian. Ce script est fait pour tourner en cron sur l'hôte
#  Docker (voir README, « Correctifs de sécurité de l'image de base »).
#
#  Usage :
#    ./rebuild-image.sh               stack docker compose de ce dossier :
#                                     reconstruit, re-tire MySQL, recrée
#                                     les conteneurs dont l'image a changé
#    ./rebuild-image.sh --image-only  stack Portainer : reconstruit
#                                     simcity:local (ou $IMAGE) et re-tire
#                                     MySQL ; le redéploiement se fait
#                                     ensuite dans Portainer
#
#  Une construction en échec arrête le script (set -e) : les conteneurs en
#  service ne sont alors pas touchés.
# ============================================================
set -eu

cd "$(dirname "$0")"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

case "${1:-}" in
    --image-only)
        IMAGE="${IMAGE:-simcity:local}"
        DB_IMAGE="${DB_IMAGE:-mysql:8.4}"
        log "Construction de $IMAGE (--pull --no-cache)"
        docker build --pull --no-cache -t "$IMAGE" .
        log "Mise à jour de $DB_IMAGE"
        docker pull "$DB_IMAGE"
        log "Images à jour : redéployer le stack dans Portainer (sans « Re-pull image »)."
        ;;
    "")
        log "Construction de l'image applicative (--pull --no-cache)"
        docker compose build --pull --no-cache app
        log "Mise à jour de l'image MySQL"
        docker compose pull db
        log "Recréation des conteneurs dont l'image a changé"
        docker compose up -d --no-build
        ;;
    *)
        echo "Usage : $0 [--image-only]" >&2
        exit 2
        ;;
esac

# Les anciennes versions, devenues sans étiquette, occuperaient sinon
# plusieurs centaines de Mo à chaque passage.
docker image prune -f >/dev/null
log "Terminé."
