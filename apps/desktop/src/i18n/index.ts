// Minimal i18n: typed message keys, `{param}` interpolation, locale switch
// point for a future English dictionary.

import { fieldLabelsRu } from "./fields.ru";
import { ru, type MessageKey } from "./ru";

type Dict = Record<MessageKey, string>;

const dictionaries: Record<string, { messages: Dict; fields: Record<string, string> }> = {
  ru: { messages: ru, fields: fieldLabelsRu },
};

let current = dictionaries.ru;
export const locale = "ru-RU";

export function setLocale(name: string): void {
  current = dictionaries[name] ?? dictionaries.ru;
}

export type Params = Record<string, string | number>;

export function t(key: MessageKey, params?: Params): string {
  const s: string = current.messages[key] ?? key;
  if (!params) return s;
  return s.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name]) : m));
}

/** Localized label for a protocol tree field, falling back to the backend name. */
export function fieldLabel(abbrev: string, fallback: string): string {
  return current.fields[abbrev] ?? fallback;
}

export type { MessageKey };
