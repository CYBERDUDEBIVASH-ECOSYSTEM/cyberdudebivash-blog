'use strict';

const fs = require('node:fs');
const path = require('node:path');

const workflow = fs.readFileSync(path.join(__dirname, '../../.github/workflows/soc-historical-backup-offline-proof.yml'), 'utf8');

describe('migrated SOC customer backup offline proof', () => {
  test('manual-only and restricted to reviewed main in the new owner repository', () => {
    expect(workflow).toContain('workflow_dispatch:');
    expect(workflow).not.toMatch(/^  schedule:/m);
    expect(workflow).toContain("github.ref == 'refs/heads/main'");
    expect(workflow).toContain("github.repository == 'CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog'");
    expect(workflow).not.toContain("github.repository == 'cyberdudebivash/cyberdudebivash-blog'");
    expect(workflow).toContain('VERIFY_RECENT_BACKUP_OFFLINE');
    expect(workflow).toContain('contents: read');
    expect(workflow).toContain('actions: read');
    expect(workflow).not.toContain('contents: write');
  });

  test('pins the transferred, unexpired Nov 13 ciphertext and audited decrypt source', () => {
    expect(workflow).toContain('customer-data-backup-43412850919');
    expect(workflow).toContain('14029734149');
    expect(workflow).toContain('sha256:db0890afa42592b70adb41d7663fa2168dd110b85c5007bd795e900e20d5cce4');
    expect(workflow).toContain('7f4fcd2c835190ac20aab7fce6550add9869de4fa2e9bd87bd391b0fdf083e15');
    expect(workflow).toContain("== '15290'");
    expect(workflow).toContain('692ee1f2f2a8894e5782972b61d3e2f820b2581f');
    expect(workflow).toContain('0933115405f0c70c22c34cdbe19ea451486fbad0');
    expect(workflow).not.toContain('customer-data-backup-42013963858');
  });

  test('decryption stays dry-run and suppresses customer evidence output', () => {
    expect(workflow).toContain('node scripts/restore-customer-data.js');
    expect(workflow).toContain('customer-data.enc" >/dev/null 2>&1');
    expect(workflow).toContain('P0_PRODUCTION_DATA_MUTATION=false');
    expect(workflow).toContain('P0_ISOLATED_REDIS_RESTORE_VERIFIED=false');
    expect(workflow).toContain('P0_RPO_RTO_VERIFIED=false');
    expect(workflow).not.toMatch(/gh workflow run|wrangler deploy/);
    expect(workflow).not.toMatch(/node scripts\/restore-customer-data\.js\s*\\\s*\n\s*[^\n]*--confirm/);
  });
});
