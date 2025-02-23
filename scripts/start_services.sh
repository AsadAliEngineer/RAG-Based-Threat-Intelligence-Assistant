#!/bin/bash
set -e

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo "[ERROR] Docker is not running. Please start Docker Desktop or the Docker daemon."
  exit 1
fi

# Start Neo4j with docker-compose
echo "[INFO] Starting Neo4j with docker-compose..."
docker-compose up -d

# Wait for Neo4j to be ready
echo "[INFO] Waiting for Neo4j to be ready..."
RETRIES=30
until docker exec neo4j cypher-shell -u neo4j -p $(echo $NEO4J_AUTH | cut -d'/' -f2) "RETURN 1" > /dev/null 2>&1; do
  sleep 2
  let RETRIES--
  if [ $RETRIES -le 0 ]; then
    echo "[ERROR] Neo4j did not become ready in time."
    exit 1
  fi
done

echo "[INFO] Neo4j is ready!" 