#!/usr/bin/env node
/**
 * DEPRECATED: The Node mock server has been removed.
 * Use the live Go management API with DuckDB instead:
 *
 *   cd go && go run ./cmd/trakshya-api/
 *   # or
 *   docker compose up --build
 *   # or (Kubernetes)
 *   kubectl apply -f k8s/
 *
 * Dashboard: http://localhost:8000
 */
console.error('TRAKSHYA: server.js mock backend was removed.');
console.error('Start the live DuckDB API: cd go && go run ./cmd/trakshya-api/');
process.exit(1);
