'use strict';

const path = require('path');
const { openDb } = require('./db');
const { CertAuthority } = require('./certAuthority');
const { RevocationRegistry } = require('./revocation');
const { AuditLog } = require('./auditLog');
const { FraudEngine } = require('./fraudEngine');
const { ReconciliationService } = require('./reconciliation');
const { createApp } = require('./app');

function buildServer(dbPath = path.join(__dirname, '..', '..', 'data', 'ledger.db')) {
  const db = openDb(dbPath);
  const certAuthority = new CertAuthority();
  const revocationRegistry = new RevocationRegistry(db);
  const auditLog = new AuditLog(db);
  const fraudEngine = new FraudEngine(db, { auditLog, revocationRegistry });
  const reconciliationService = new ReconciliationService(db, {
    auditLog,
    fraudEngine,
    revocationRegistry
  });

  const app = createApp({
    db,
    certAuthority,
    reconciliationService,
    revocationRegistry,
    auditLog
  });

  return { app, db, certAuthority, revocationRegistry, auditLog, fraudEngine, reconciliationService };
}

if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  const { app } = buildServer();
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Reconciliation Service (Ingest API) listening on :${PORT}`);
  });
}

module.exports = { buildServer };
