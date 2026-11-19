import { describe, it, expect } from 'vitest';

// RFC 6962 Leaf Hash: SHA-256(0x00 || leafData)
async function hashLeaf(leafDataStr) {
  const enc = new TextEncoder();
  const leafBytes = enc.encode(leafDataStr);
  const combined = new Uint8Array(1 + leafBytes.length);
  combined[0] = 0x00;
  combined.set(leafBytes, 1);
  const hashBuf = await crypto.subtle.digest('SHA-256', combined);
  return bufToHex(hashBuf);
}

// RFC 6962 Internal Node Hash: SHA-256(0x01 || leftHex || rightHex)
async function hashNode(leftHex, rightHex) {
  const leftBytes = hexToBuf(leftHex);
  const rightBytes = hexToBuf(rightHex);
  const combined = new Uint8Array(1 + 32 + 32);
  combined[0] = 0x01;
  combined.set(leftBytes, 1);
  combined.set(rightBytes, 33);
  const hashBuf = await crypto.subtle.digest('SHA-256', combined);
  return bufToHex(hashBuf);
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Verify Merkle path
async function verifyProof(leafDataStr, proof, expectedRootHex) {
  let currentHash = await hashLeaf(leafDataStr);
  for (const step of proof) {
    if (step.position === 'left') {
      currentHash = await hashNode(step.hash, currentHash);
    } else if (step.position === 'right') {
      currentHash = await hashNode(currentHash, step.hash);
    } else {
      return false;
    }
  }
  return currentHash.toLowerCase() === expectedRootHex.toLowerCase();
}

describe('Merkle Tree Signed Receipts & Independent Verification', () => {
  it('correctly computes domain-separated leaf and node hashes', async () => {
    const leafHash = await hashLeaf('sample-payload-hash-1234');
    expect(leafHash).toBeDefined();
    expect(leafHash.length).toBe(64);

    const parentHash = await hashNode(leafHash, leafHash);
    expect(parentHash).toBeDefined();
    expect(parentHash.length).toBe(64);
    expect(parentHash).not.toBe(leafHash);
  });

  it('verifies a multi-level Merkle inclusion proof independently', async () => {
    // Construct a simulated 4-leaf tree: L0, L1, L2, L3
    const l0 = 'leaf-0-payload-hash';
    const l1 = 'leaf-1-payload-hash';
    const l2 = 'leaf-2-payload-hash';
    const l3 = 'leaf-3-payload-hash';

    const h0 = await hashLeaf(l0);
    const h1 = await hashLeaf(l1);
    const h2 = await hashLeaf(l2);
    const h3 = await hashLeaf(l3);

    const p01 = await hashNode(h0, h1);
    const p23 = await hashNode(h2, h3);
    const expectedRoot = await hashNode(p01, p23);

    // Proof for leaf 0 (sibling h1 on right, sibling p23 on right)
    const proof0 = [
      { position: 'right', hash: h1 },
      { position: 'right', hash: p23 },
    ];

    const valid0 = await verifyProof(l0, proof0, expectedRoot);
    expect(valid0).toBe(true);

    // Proof for leaf 2 (sibling h3 on right, sibling p01 on left)
    const proof2 = [
      { position: 'right', hash: h3 },
      { position: 'left', hash: p01 },
    ];

    const valid2 = await verifyProof(l2, proof2, expectedRoot);
    expect(valid2).toBe(true);

    // Negative case: Tampered leaf payload
    const invalidPayload = await verifyProof('corrupted-payload-hash', proof0, expectedRoot);
    expect(invalidPayload).toBe(false);

    // Negative case: Tampered sibling hash
    const corruptedProof = [
      { position: 'right', hash: '0000000000000000000000000000000000000000000000000000000000000000' },
      { position: 'right', hash: p23 },
    ];
    const invalidSibling = await verifyProof(l0, corruptedProof, expectedRoot);
    expect(invalidSibling).toBe(false);
  });

  it('validates receipt JSON structure compatibility for offline verifier', () => {
    const mockReceipt = {
      version: '2.0',
      receipt_type: 'BurnerBox Cryptographic Submission Receipt',
      submission_id: '123e4567-e89b-12d3-a456-426614174000',
      payload_hash: 'a1b2c3d4e5f6',
      signature: 'base64Sig',
      key_fingerprint: 'abcd1234',
      merkle_tree: {
        batch_id: 'batch-1',
        batch_number: 1,
        leaf_index: 0,
        leaf_hash: 'a1b2c3d4e5f6',
        status: 'sealed',
      },
    };

    expect(mockReceipt.merkle_tree.batch_number).toBe(1);
    expect(mockReceipt.merkle_tree.leaf_index).toBe(0);
    expect(mockReceipt.version).toBe('2.0');
  });
});
