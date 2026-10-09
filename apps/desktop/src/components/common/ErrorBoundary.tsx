import { Component, type ErrorInfo, type ReactNode } from "react";

import { t } from "../../i18n";

interface Props {
  children: ReactNode;
  /** Changing the key value resets the boundary (e.g. new capture, other tab). */
  resetKey?: unknown;
}

interface State {
  error: Error | null;
  resetKey: unknown;
}

/** Keeps a failing panel from unmounting the whole application. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, resetKey: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    return props.resetKey !== state.resetKey ? { error: null, resetKey: props.resetKey } : null;
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("UI panel failed:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="tool-note" role="alert">
          <div style={{ color: "var(--error)", marginBottom: 8 }}>{t("common.error", { message: this.state.error.message })}</div>
          <button className="btn btn-small" onClick={() => this.setState({ error: null })}>
            {t("status.retry")}
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
