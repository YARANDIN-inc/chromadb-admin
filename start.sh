#!/bin/bash

echo "🚀 Starting ChromaDB Admin Panel..."
echo "=================================="

# Check if docker compose is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Start the services
echo "📦 Starting services with Docker Compose..."
docker compose up -d

# Wait a moment for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check if services are running
echo "🔍 Checking service status..."
docker compose ps

echo ""
echo "✅ ChromaDB Admin Panel is running!"
echo ""
echo "🌐 Access the application at:"
echo "   Admin Panel:  http://localhost:8080"
echo "   ChromaDB API: http://localhost:8001"
echo ""
echo "📊 Default credentials:"
echo "   PostgreSQL: postgres/postgres"
echo ""
echo "📝 View logs with:"
echo "   docker compose logs -f web"
echo ""
echo "🛑 Stop services with:"
echo "   docker compose down"
echo ""

# Follow logs
echo "📊 Following application logs (Ctrl+C to stop)..."
sleep 2
docker compose logs -f web 