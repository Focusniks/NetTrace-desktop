import { useCallback, useRef, useState } from "react";

interface Props {
  direction: "horizontal" | "vertical";
  /** Called with the pointer delta (px) since drag start. */
  onDrag: (delta: number) => void;
  onEnd?: () => void;
}

/** Drag handle between two panes (horizontal = resizes heights). */
export function Splitter({ direction, onDrag, onEnd }: Props) {
  const start = useRef(0);
  const [dragging, setDragging] = useState(false);

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      e.preventDefault();
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
      start.current = direction === "horizontal" ? e.clientY : e.clientX;
      setDragging(true);
    },
    [direction],
  );

  const onPointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (!dragging) return;
      const pos = direction === "horizontal" ? e.clientY : e.clientX;
      onDrag(pos - start.current);
    },
    [dragging, direction, onDrag],
  );

  const onPointerUp = useCallback(() => {
    setDragging(false);
    onEnd?.();
  }, [onEnd]);

  return (
    <div
      className={`${direction === "horizontal" ? "splitter-h" : "splitter-v"}${dragging ? " is-dragging" : ""}`}
      role="separator"
      aria-orientation={direction === "horizontal" ? "horizontal" : "vertical"}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
    />
  );
}
