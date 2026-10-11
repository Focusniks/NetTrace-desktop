// Turns followed-stream chunks into display lines (text or hex dump).
//
// Stream bytes are untrusted: everything that is not printable is shown as an
// escape (`\xNN`, `\u{NNNN}`), including Unicode bidi and other invisible
// format characters that could make the text read differently from the bytes.

import type { FollowChunk } from "../api/types";

export type FollowMode = "text" | "hex";

export interface FollowLine {
  kind: "data" | "gap" | "notCaptured";
  direction: "c2s" | "s2c";
  /** Packet the line starts in. */
  number: number;
  /** Output offset of the first byte of the line. */
  offset: number;
  text: string;
  /** Hole size in bytes (gap / notCaptured lines). */
  len?: number;
}

/** Longer text lines are wrapped so a binary stream without newlines stays usable. */
export const MAX_LINE = 256;
const HEX_ROW = 16;

export function decodeChunk(data: string): Uint8Array {
  const bin = atob(data);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const hex2 = (b: number) => b.toString(16).padStart(2, "0");

/** Controls, format characters (bidi, zero-width), private use, unassigned, line/paragraph separators. */
const HIDDEN = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u;
const COMBINING = /\p{M}/u;

/** Code points that are not shown as themselves: they are invisible or could disguise the text. */
function invisible(cp: number): boolean {
  return (
    HIDDEN.test(String.fromCodePoint(cp)) ||
    // Blank-looking letters and fillers, variation selectors, noncharacters.
    cp === 0x034f ||
    cp === 0x115f ||
    cp === 0x1160 ||
    cp === 0x180e ||
    cp === 0x3164 ||
    cp === 0xffa0 ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef) ||
    (cp & 0xfffe) === 0xfffe
  );
}

/** Length of a valid UTF-8 sequence at `i` and its code point, or null. */
function utf8At(b: Uint8Array, i: number): [number, number] | null {
  const c = b[i];
  let n: number;
  let cp: number;
  if (c >= 0xc2 && c <= 0xdf) [n, cp] = [2, c & 0x1f];
  else if (c >= 0xe0 && c <= 0xef) [n, cp] = [3, c & 0x0f];
  else if (c >= 0xf0 && c <= 0xf4) [n, cp] = [4, c & 0x07];
  else return null;
  if (i + n > b.length) return null;
  for (let k = 1; k < n; k++) {
    const x = b[i + k];
    if ((x & 0xc0) !== 0x80) return null;
    cp = (cp << 6) | (x & 0x3f);
  }
  // Overlong forms, surrogates and values past U+10FFFF are invalid.
  if ((n === 3 && cp < 0x800) || (n === 4 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff)) return null;
  return [n, cp];
}

/**
 * Builds display lines incrementally: chunks arrive page by page, and a text
 * line or hex row may continue across chunks of the same direction.
 */
export class LineBuilder {
  readonly lines: FollowLine[] = [];
  private open: FollowLine | null = null;
  /** Bytes of the open hex row (its text is rebuilt as it fills). */
  private row: number[] = [];
  /** Bytes of an incomplete UTF-8 sequence at the end of the last chunk. */
  private pending: number[] = [];
  /** A `\r` waiting to see whether `\n` follows. */
  private cr = false;
  /** Output offset the open line continues at. */
  private next = -1;
  /** Offset and packet of the byte being appended (start of a wrapped row). */
  private at = 0;
  private atNumber = 0;
  /** The last character shown was a combining mark (a second one in a row is escaped). */
  private mark = false;

  constructor(readonly mode: FollowMode) {}

  push(c: FollowChunk): void {
    if (c.kind !== "data") {
      this.close();
      this.lines.push({ kind: c.kind, direction: c.direction, number: c.number, offset: c.offset, text: "", len: c.len });
      return;
    }
    const bytes = decodeChunk(c.data ?? "");
    if (this.open && (this.open.direction !== c.direction || this.next !== c.offset)) this.close();
    if (this.mode === "hex") this.pushHex(c, bytes);
    else this.pushText(c, bytes);
    this.next = c.offset + bytes.length;
  }

  /** Ends the open line (end of stream, or before a hole / direction change). */
  close(): void {
    if (this.pending.length) {
      const bytes = this.pending;
      this.pending = [];
      for (const b of bytes) this.append(`\\x${hex2(b)}`);
    }
    if (this.cr) {
      this.cr = false;
      this.append("\\r");
    }
    this.open = null;
    this.row = [];
    this.mark = false;
  }

  private start(c: FollowChunk, offset: number): FollowLine {
    const line: FollowLine = { kind: "data", direction: c.direction, number: c.number, offset, text: "" };
    this.lines.push(line);
    this.open = line;
    return line;
  }

  /** Appends to the open text line, wrapping at MAX_LINE. */
  private append(s: string): void {
    let line = this.open;
    if (!line) return;
    if (line.text.length + s.length > MAX_LINE && line.text.length > 0) {
      line = { ...line, number: this.atNumber, offset: this.at, text: "" };
      this.lines.push(line);
      this.open = line;
    }
    line.text += s;
  }

  private pushText(c: FollowChunk, chunk: Uint8Array): void {
    let b = chunk;
    if (this.pending.length) {
      b = new Uint8Array(this.pending.length + chunk.length);
      b.set(this.pending);
      b.set(chunk, this.pending.length);
    }
    const base = c.offset - this.pending.length;
    this.pending = [];
    let i = 0;
    this.atNumber = c.number;
    while (i < b.length) {
      if (!this.open) this.start(c, base + i);
      this.at = base + i;
      const x = b[i];
      if (this.cr) {
        this.cr = false;
        if (x !== 0x0a) this.append("\\r");
      }
      if (x === 0x0a) {
        this.open = null;
        this.mark = false;
        i++;
        continue;
      }
      if (x === 0x0d) {
        this.cr = true;
        i++;
        continue;
      }
      if (x === 0x09 || (x >= 0x20 && x < 0x7f)) {
        this.append(String.fromCharCode(x));
        this.mark = false;
        i++;
        continue;
      }
      const u = utf8At(b, i);
      if (u) {
        const [n, cp] = u;
        const ch = String.fromCodePoint(cp);
        // Stacked combining marks would draw over neighbouring rows.
        const mark = COMBINING.test(ch);
        const shown = !invisible(cp) && !(mark && this.mark);
        this.append(shown ? ch : `\\u{${cp.toString(16).toUpperCase().padStart(4, "0")}}`);
        this.mark = shown && mark;
        i += n;
        continue;
      }
      // A sequence cut by the chunk end may complete in the next chunk.
      if (x >= 0xc2 && x <= 0xf4 && b.length - i < 4 && this.prefixOk(b, i)) {
        this.pending = Array.from(b.subarray(i));
        break;
      }
      this.append(`\\x${hex2(x)}`);
      this.mark = false;
      i++;
    }
  }

  /** The bytes from `i` to the end are a valid start of a longer UTF-8 sequence. */
  private prefixOk(b: Uint8Array, i: number): boolean {
    const need = b[i] >= 0xf0 ? 4 : b[i] >= 0xe0 ? 3 : 2;
    if (b.length - i >= need) return false;
    for (let k = i + 1; k < b.length; k++) if ((b[k] & 0xc0) !== 0x80) return false;
    return true;
  }

  private pushHex(c: FollowChunk, b: Uint8Array): void {
    for (let i = 0; i < b.length; ) {
      if (!this.open) this.start(c, c.offset + i);
      const take = Math.min(HEX_ROW - this.row.length, b.length - i);
      for (let k = 0; k < take; k++) this.row.push(b[i + k]);
      i += take;
      const line = this.open as FollowLine;
      line.text = hexRow(line.offset, this.row);
      if (this.row.length === HEX_ROW) {
        this.open = null;
        this.row = [];
      }
    }
  }
}

function hexRow(offset: number, bytes: number[]): string {
  let hex = "";
  let ascii = "";
  for (let k = 0; k < HEX_ROW; k++) {
    hex += k < bytes.length ? hex2(bytes[k]) : "  ";
    hex += k === 7 ? "  " : " ";
    if (k < bytes.length) ascii += bytes[k] >= 0x20 && bytes[k] < 0x7f ? String.fromCharCode(bytes[k]) : ".";
  }
  return `${offset.toString(16).padStart(8, "0")}  ${hex} ${ascii}`;
}

/** All lines for a list of chunks (convenience for a finished stream). */
export function buildLines(chunks: FollowChunk[], mode: FollowMode): FollowLine[] {
  const b = new LineBuilder(mode);
  for (const c of chunks) b.push(c);
  b.close();
  return b.lines;
}
