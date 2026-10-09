import type { PacketField } from "../api/types";

/** Stable expansion key: path of field abbreviations (or labels for text nodes). */
export function expansionKey(parent: string, node: PacketField): string {
  const id = node.field || node.name.split(/[:(,]/)[0].trim();
  return parent ? `${parent}/${id}` : id;
}

export interface FlatNode {
  node: PacketField;
  depth: number;
  /** Index path, e.g. "3/0/2" — identifies the node in this packet. */
  path: string;
  expKey: string;
  hasChildren: boolean;
  expanded: boolean;
  parentPath: string | null;
}

export function flatten(tree: PacketField[], expanded: Set<string>): FlatNode[] {
  const out: FlatNode[] = [];
  const walk = (nodes: PacketField[], depth: number, parentPath: string | null, parentExp: string) => {
    nodes.forEach((node, i) => {
      const path = parentPath === null ? String(i) : `${parentPath}/${i}`;
      const expKey = expansionKey(parentExp, node);
      const hasChildren = node.children.length > 0;
      const isExpanded = hasChildren && expanded.has(expKey);
      out.push({ node, depth, path, expKey, hasChildren, expanded: isExpanded, parentPath });
      if (isExpanded) walk(node.children, depth + 1, path, expKey);
    });
  };
  walk(tree, 0, null, "");
  return out;
}

export function nodeAt(tree: PacketField[], path: string): PacketField | null {
  let nodes = tree;
  let node: PacketField | null = null;
  for (const part of path.split("/")) {
    node = nodes[Number(part)] ?? null;
    if (!node) return null;
    nodes = node.children;
  }
  return node;
}

/** Expansion keys of all ancestors of `path` (so the node becomes visible). */
export function ancestorKeys(tree: PacketField[], path: string): string[] {
  const keys: string[] = [];
  let nodes = tree;
  let exp = "";
  const parts = path.split("/");
  for (let i = 0; i < parts.length - 1; i++) {
    const node = nodes[Number(parts[i])];
    if (!node) break;
    exp = expansionKey(exp, node);
    keys.push(exp);
    nodes = node.children;
  }
  return keys;
}

/**
 * Smallest node whose byte range covers `offset` (protocol tree ↔ hex link).
 * On a tie the first one in tree order wins, i.e. a field over its bit fields.
 */
export function deepestAt(tree: PacketField[], offset: number): string | null {
  let best: string | null = null;
  let bestLen = Infinity;
  const walk = (nodes: PacketField[], parent: string | null) => {
    nodes.forEach((n, i) => {
      const path = parent === null ? String(i) : `${parent}/${i}`;
      if (n.len > 0 && offset >= n.start && offset < n.start + n.len) {
        if (n.len < bestLen) {
          best = path;
          bestLen = n.len;
        }
      }
      if (n.children.length) walk(n.children, path);
    });
  };
  // Skip the frame node: it covers everything.
  tree.forEach((n, i) => {
    if (n.field !== "frame") {
      const path = String(i);
      if (n.len > 0 && offset >= n.start && offset < n.start + n.len && n.len < bestLen) {
        best = path;
        bestLen = n.len;
      }
      walk(n.children, path);
    }
  });
  return best;
}

export function allExpansionKeys(tree: PacketField[]): string[] {
  const out: string[] = [];
  const walk = (nodes: PacketField[], parent: string) => {
    for (const n of nodes) {
      const k = expansionKey(parent, n);
      if (n.children.length) {
        out.push(k);
        walk(n.children, k);
      }
    }
  };
  walk(tree, "");
  return out;
}
