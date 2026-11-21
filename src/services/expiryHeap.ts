export interface ExpiryEntry {
  key: string;
  expiresAt: number;
}

/** Binary min-heap ordered by expiresAt, so the soonest-to-expire entry is on top. */
export class ExpiryHeap {
  private items: ExpiryEntry[] = [];

  get size(): number {
    return this.items.length;
  }

  /** Replaces the contents with the given entries, rebuilding heap order. */
  rebuild(entries: Iterable<ExpiryEntry>): void {
    this.items = [];
    for (const entry of entries) this.push(entry);
  }

  peek(): ExpiryEntry | undefined {
    return this.items[0];
  }

  push(entry: ExpiryEntry): void {
    const items = this.items;
    items.push(entry);
    let i = items.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (items[parent].expiresAt <= items[i].expiresAt) break;
      [items[parent], items[i]] = [items[i], items[parent]];
      i = parent;
    }
  }

  pop(): ExpiryEntry | undefined {
    const items = this.items;
    const top = items[0];
    const last = items.pop();
    if (items.length > 0 && last) {
      items[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let smallest = i;
        if (l < items.length && items[l].expiresAt < items[smallest].expiresAt) smallest = l;
        if (r < items.length && items[r].expiresAt < items[smallest].expiresAt) smallest = r;
        if (smallest === i) break;
        [items[smallest], items[i]] = [items[i], items[smallest]];
        i = smallest;
      }
    }
    return top;
  }
}
