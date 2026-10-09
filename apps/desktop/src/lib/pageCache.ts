// Page cache for tables served page by page by the backend (hosts,
// conversations, streams). Only pages near the visible window are kept.

export interface Page<T> {
  total: number;
  rows: T[];
}

export class PageCache<T> {
  /** Known number of rows (null until the first page arrives). */
  total: number | null = null;
  private pages = new Map<number, T[]>();
  /** Pages of the previous refresh, shown until fresh rows arrive (no blinking). */
  private stale = new Map<number, T[]>();
  private pending = new Set<number>();
  private failed = new Set<number>();
  /** Responses to requests of an older generation are dropped. */
  private generation = 0;

  constructor(
    readonly pageSize = 200,
    readonly maxPages = 50,
  ) {}

  get(i: number): T | undefined {
    const p = Math.floor(i / this.pageSize);
    const page = this.pages.get(p);
    if (page) {
      // Map order is the LRU order: re-insert on use.
      this.pages.delete(p);
      this.pages.set(p, page);
      return page[i % this.pageSize];
    }
    return this.stale.get(p)?.[i % this.pageSize];
  }

  hasPending(): boolean {
    return this.pending.size > 0;
  }

  /** Pages to request so rows `first .. first + count` are available. */
  missing(first: number, count: number): number[] {
    const out: number[] = [];
    const last = this.total == null ? first : Math.min(first + Math.max(count, 1), this.total) - 1;
    for (let p = Math.floor(first / this.pageSize); p <= Math.floor(Math.max(first, last) / this.pageSize); p++) {
      if (!this.pages.has(p) && !this.pending.has(p) && !this.failed.has(p)) out.push(p);
    }
    return out;
  }

  /** Marks a page as requested; returns the generation to pass back. */
  begin(page: number): number {
    this.pending.add(page);
    return this.generation;
  }

  /** Stores a page; false when the response is outdated. */
  done(page: number, generation: number, result: Page<T>): boolean {
    if (generation !== this.generation) return false;
    this.pending.delete(page);
    this.total = result.total;
    this.pages.delete(page);
    this.pages.set(page, result.rows);
    this.stale.delete(page);
    for (const p of this.pages.keys()) {
      if (this.pages.size <= this.maxPages) break;
      this.pages.delete(p);
    }
    return true;
  }

  /** A request that was superseded on the backend: ask again later. */
  cancel(page: number, generation: number): void {
    if (generation === this.generation) this.pending.delete(page);
  }

  /** Records a failed page (not retried until `retry`); false when outdated. */
  fail(page: number, generation: number): boolean {
    if (generation !== this.generation) return false;
    this.pending.delete(page);
    this.failed.add(page);
    return true;
  }

  /**
   * New data for the same query: refetch, showing the current rows meanwhile.
   * Requests already under way still land (their rows are as valid).
   */
  refresh(): void {
    for (const [p, rows] of this.pages) this.stale.set(p, rows);
    this.pages.clear();
    this.failed.clear();
  }

  /** A different query (order, filter, capture): nothing old is valid. */
  reset(): void {
    this.generation++;
    this.pages.clear();
    this.stale.clear();
    this.pending.clear();
    this.failed.clear();
    this.total = null;
  }

  retry(): void {
    this.failed.clear();
  }
}
