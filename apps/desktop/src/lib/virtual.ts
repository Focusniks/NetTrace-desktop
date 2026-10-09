// Virtual scrolling math for very long lists.
//
// Browsers cap element height (~33M px in Chromium), so lists taller than
// MAX_SCROLL_PX are compressed: the scrollbar maps linearly onto rows.

export const MAX_SCROLL_PX = 8_000_000;

export interface Window {
  /** Height of the scroll content in px. */
  contentHeight: number;
  /** First row to render. */
  first: number;
  /** Number of rows to render. */
  count: number;
  /** Translation of the first rendered row inside the viewport (px). */
  offsetY: number;
}

export function computeWindow(total: number, rowHeight: number, viewport: number, scrollTop: number, overscan = 4): Window {
  const natural = total * rowHeight;
  const visible = Math.ceil(viewport / rowHeight) + 1;
  if (natural <= MAX_SCROLL_PX) {
    const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
    const count = Math.min(total - first, visible + overscan * 2);
    return { contentHeight: natural, first, count: Math.max(0, count), offsetY: first * rowHeight };
  }
  // Compressed: scrollTop ∈ [0, MAX-viewport] ↦ topRow ∈ [0, total-visible].
  const scrollable = Math.max(1, MAX_SCROLL_PX - viewport);
  const ratio = Math.min(1, Math.max(0, scrollTop / scrollable));
  const maxTop = Math.max(0, total - Math.floor(viewport / rowHeight));
  const top = Math.round(ratio * maxTop);
  const first = Math.max(0, top - overscan);
  const count = Math.min(total - first, visible + overscan * 2);
  // Rows are drawn relative to the viewport top (scrollTop), not to their natural offset.
  return { contentHeight: MAX_SCROLL_PX, first, count: Math.max(0, count), offsetY: scrollTop - (top - first) * rowHeight };
}

/** scrollTop that puts `row` at the top (or keeps it visible when `ensure` is set). */
export function scrollTopForRow(
  row: number,
  total: number,
  rowHeight: number,
  viewport: number,
  currentScrollTop: number,
  ensure: boolean,
): number {
  const natural = total * rowHeight;
  if (natural <= MAX_SCROLL_PX) {
    const y = row * rowHeight;
    if (!ensure) return y;
    if (y < currentScrollTop) return y;
    if (y + rowHeight > currentScrollTop + viewport) return y + rowHeight - viewport;
    return currentScrollTop;
  }
  const rowsVisible = Math.floor(viewport / rowHeight);
  const maxTop = Math.max(1, total - rowsVisible);
  const scrollable = Math.max(1, MAX_SCROLL_PX - viewport);
  const currentTop = Math.round((currentScrollTop / scrollable) * maxTop);
  let top = row;
  if (ensure) {
    if (row >= currentTop && row < currentTop + rowsVisible - 1) return currentScrollTop;
    top = row < currentTop ? row : row - rowsVisible + 2;
  }
  top = Math.min(maxTop, Math.max(0, top));
  return (top / maxTop) * scrollable;
}
