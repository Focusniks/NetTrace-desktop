import { describe, expect, it } from "vitest";

import type { FollowChunk } from "../api/types";
import { buildLines, decodeChunk, LineBuilder, MAX_LINE } from "./follow";

function b64(bytes: number[] | string): string {
  const arr = typeof bytes === "string" ? Array.from(new TextEncoder().encode(bytes)) : bytes;
  return btoa(String.fromCharCode(...arr));
}

function data(offset: number, bytes: number[] | string, direction: "c2s" | "s2c" = "c2s", number = 1): FollowChunk {
  const data = b64(bytes);
  const len = atob(data).length;
  return { kind: "data", direction, number, offset, streamOffset: offset, len, data };
}

const texts = (chunks: FollowChunk[], mode: "text" | "hex" = "text") => buildLines(chunks, mode).map((l) => l.text);

describe("decodeChunk", () => {
  it("decodes base64 to bytes", () => {
    expect(Array.from(decodeChunk(b64([0, 255, 10])))).toEqual([0, 255, 10]);
  });
});

describe("text lines", () => {
  it("splits on newlines and drops the CR of CRLF", () => {
    expect(texts([data(0, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")])).toEqual(["GET / HTTP/1.1", "Host: a", ""]);
  });

  it("continues a line across chunks and starts a new one on direction change", () => {
    const lines = buildLines([data(0, "ab"), data(2, "cd\n", "c2s", 2), data(5, "ok", "s2c", 3)], "text");
    expect(lines.map((l) => [l.text, l.direction, l.number, l.offset])).toEqual([
      ["abcd", "c2s", 1, 0],
      ["ok", "s2c", 3, 5],
    ]);
  });

  it("escapes control bytes, invalid UTF-8 and a lone CR", () => {
    expect(texts([data(0, [0x41, 0x00, 0x1b, 0xff, 0x0d, 0x42])])).toEqual(["A\\x00\\x1b\\xff\\rB"]);
  });

  it("shows valid UTF-8 and escapes bidi and invisible characters", () => {
    expect(texts([data(0, "привет ‮abc​")])).toEqual(["привет \\u{202E}abc\\u{200B}"]);
  });

  it("joins a UTF-8 character split between chunks", () => {
    const [a, b] = [Array.from(new TextEncoder().encode("ж")), [0x21]];
    expect(texts([data(0, [a[0]]), data(1, [a[1], ...b])])).toEqual(["ж!"]);
    // A truncated sequence at the end of the stream is escaped.
    expect(texts([data(0, [0x41, a[0]])])).toEqual(["A\\xd0"]);
  });

  it("rejects overlong and surrogate encodings", () => {
    expect(texts([data(0, [0xc0, 0xaf, 0xed, 0xa0, 0x80])])).toEqual(["\\xc0\\xaf\\xed\\xa0\\x80"]);
  });

  it("wraps very long lines", () => {
    const lines = texts([data(0, "x".repeat(MAX_LINE * 2 + 5))]);
    expect(lines.map((l) => l.length)).toEqual([MAX_LINE, MAX_LINE, 5]);
  });

  it("puts holes on their own lines", () => {
    const gap: FollowChunk = { kind: "gap", direction: "c2s", number: 3, offset: 2, streamOffset: 2, len: 50 };
    const lines = buildLines([data(0, "ab"), gap, data(2, "cd", "c2s", 3)], "text");
    expect(lines.map((l) => [l.kind, l.text, l.len])).toEqual([
      ["data", "ab", undefined],
      ["gap", "", 50],
      ["data", "cd", undefined],
    ]);
  });

  it("starts a new line when the output offset is not contiguous", () => {
    expect(texts([data(0, "ab"), data(10, "cd")])).toEqual(["ab", "cd"]);
  });
});

describe("hex lines", () => {
  it("dumps 16 bytes per row with offsets and ASCII", () => {
    const bytes = Array.from({ length: 20 }, (_, i) => 0x41 + i);
    const lines = texts([data(0, bytes.slice(0, 10)), data(10, bytes.slice(10))], "hex");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  ABCDEFGHIJKLMNOP");
    expect(lines[1].startsWith("00000010  51 52 53 54")).toBe(true);
    expect(lines[1].endsWith("QRST")).toBe(true);
  });

  it("shows non-printable bytes as dots", () => {
    expect(texts([data(0, [0x00, 0x41, 0xff])], "hex")[0].endsWith(" .A.")).toBe(true);
  });

  it("builds incrementally the same as all at once", () => {
    const chunks = [data(0, "hello\nwor"), data(9, "ld\n", "c2s", 2), data(12, "bye", "s2c", 3)];
    const b = new LineBuilder("text");
    for (const c of chunks) b.push(c);
    b.close();
    expect(b.lines).toEqual(buildLines(chunks, "text"));
  });
});

describe("edge cases", () => {
  it("keeps a CRLF split between chunks", () => {
    expect(texts([data(0, "a\r"), data(2, "\nb")])).toEqual(["a", "b"]);
  });

  it("escapes a cut UTF-8 sequence when a hole or the other direction follows", () => {
    const gap: FollowChunk = { kind: "gap", direction: "c2s", number: 2, offset: 2, streamOffset: 2, len: 5 };
    expect(buildLines([data(0, [0x41, 0xd0]), gap], "text").map((l) => l.text)).toEqual(["A\\xd0", ""]);
    expect(texts([data(0, [0x41, 0xe2, 0x82]), data(3, "ok", "s2c")])).toEqual(["A\\xe2\\x82", "ok"]);
  });

  it("escapes a prefix that turns out invalid", () => {
    expect(texts([data(0, [0xe0]), data(1, [0x80, 0x80])])).toEqual(["\\xe0\\x80\\x80"]);
  });

  it("escapes fillers, variation selectors and stacked combining marks", () => {
    expect(texts([data(0, "a\u3164b\uFE0F")])).toEqual(["a\\u{3164}b\\u{FE0F}"]);
    expect(texts([data(0, "e\u0301\u0301")])).toEqual(["e\u0301\\u{0301}"]);
  });

  it("gives wrapped rows the offset of their first byte", () => {
    const lines = buildLines([data(10, "x".repeat(MAX_LINE + 3))], "text");
    expect(lines.map((l) => l.offset)).toEqual([10, 10 + MAX_LINE]);
  });

  it("ends a hex row at a direction change", () => {
    const lines = texts([data(0, [1, 2, 3]), data(3, [4], "s2c")], "hex");
    expect(lines).toHaveLength(2);
    expect(lines[1].startsWith("00000003  04 ")).toBe(true);
  });
});
