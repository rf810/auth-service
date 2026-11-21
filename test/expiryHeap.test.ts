import { test } from "node:test";
import assert from "node:assert/strict";
import { ExpiryHeap } from "../src/services/expiryHeap.ts";

test("pops entries in expiresAt order regardless of insertion order", () => {
  const heap = new ExpiryHeap();
  const values = [50, 10, 40, 30, 20, 60, 5, 45];
  for (const v of values) heap.push({ key: String(v), expiresAt: v });
  const out: number[] = [];
  while (heap.size) out.push(heap.pop()!.expiresAt);
  assert.deepEqual(out, [...values].sort((a, b) => a - b));
});
