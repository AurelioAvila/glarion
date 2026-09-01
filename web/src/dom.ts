// Small DOM helpers.
//
// The point of this file is that nothing in the app ever needs `innerHTML`.
// Findings, evidence and domains all originate from a scanner pointed at
// somebody else's website, so treating any of it as markup would put script
// from a scanned site into the agency's dashboard — on the same origin as
// their authenticated session. Text always goes through `textContent`, which the
// browser cannot interpret as markup.

type Attrs = Record<string, string | number | boolean | undefined>;

/// Creates an element, sets attributes, and appends children.
///
/// Children that are strings become text nodes rather than markup. That is
/// the whole safety property: there is no code path here that parses a
/// string as HTML.
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Array<Node | string | null | undefined> = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;

    if (key === "class") {
      node.className = String(value);
    } else if (key === "text") {
      node.textContent = String(value);
    } else if (key.startsWith("data-") || key === "type" || key === "role") {
      node.setAttribute(key, String(value));
    } else if (value === true) {
      node.setAttribute(key, "");
    } else {
      node.setAttribute(key, String(value));
    }
  }

  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }

  return node;
}

export function clear(node: Element): void {
  node.replaceChildren();
}

export function on<K extends keyof HTMLElementEventMap>(
  node: Element,
  event: K,
  handler: (event: HTMLElementEventMap[K]) => void,
): void {
  node.addEventListener(event, handler as EventListener);
}

export function byId<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing element #${id}`);
  return node as T;
}

/// A value the user needs to paste elsewhere, with a button that copies it.
///
/// Verification asks people to move a long random token into their DNS
/// panel. Retyping it is the most likely way for that step to fail, so the
/// token is never presented without a way to copy it exactly.
export function copyableValue(value: string, label: string): HTMLElement {
  const field = el("code", { class: "copyable-value", text: value });
  const button = el("button", {
    class: "copy-button",
    type: "button",
    "aria-label": `Copy ${label}`,
    text: "Copy",
  });

  on(button, "click", () => {
    void navigator.clipboard
      .writeText(value)
      .then(() => {
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1600);
      })
      .catch(() => {
        // Clipboard access can be refused. Select the text instead so the
        // user can copy manually rather than being left with a dead button.
        button.textContent = "Select it";
        const range = document.createRange();
        range.selectNodeContents(field);
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
      });
  });

  return el("div", { class: "copyable" }, [field, button]);
}

/// A labelled row in a definition list.
export function detailRow(label: string, value: Node | string): HTMLElement {
  return el("div", { class: "detail-row" }, [
    el("span", { class: "detail-label", text: label }),
    typeof value === "string" ? el("span", { text: value }) : value,
  ]);
}

/// Appends children, skipping the ones that turned out not to apply.
///
/// Views build lists with conditional entries (`condition ? node : null`);
/// this keeps that readable without every call site filtering by hand.
export function append(
  parent: Element,
  ...children: Array<Node | string | null | undefined>
): void {
  for (const child of children) {
    if (child === null || child === undefined) continue;
    parent.append(child);
  }
}
