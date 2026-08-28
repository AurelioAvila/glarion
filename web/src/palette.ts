// The command palette, and the keyboard model around it.
//
// Somebody who looks after twenty client sites opens this tool several
// times a day and always wants one of two things: a particular site, or a
// particular action on it. Hunting for either with a mouse is the slow path
// through an interface that already knows every site's name.
//
// So the palette is the primary way to move: one key, type a few letters,
// enter. The rest of the interface stays clickable, but the fast path is
// meant to be the keyboard — the way it is in the tools professionals keep
// open all day, and the way it is in almost nothing else in this market.

import { el, on } from "./dom.js";

export interface Command {
  /// What the reader sees.
  label: string;
  /// Shown in grey beside the label — a client name, a section.
  detail?: string;
  /// Matched against as well as the label, so "acme" finds a site whose
  /// label is the domain but whose client is Acme.
  keywords?: string;
  /// Grouped under this heading.
  group: string;
  run: () => void;
}

let overlay: HTMLElement | null = null;
let provider: (() => Command[]) | null = null;

/// Registers what the palette should offer. Views call this as they render,
/// so the palette always reflects the data currently on screen rather than
/// a stale copy fetched when it opened.
export function setCommands(source: () => Command[]): void {
  provider = source;
}

/// Ranks a command against what has been typed.
///
/// Subsequence matching, not substring: "acl" should find
/// "acme-client.com", because that is how people actually type when they
/// half-remember a name. Returns null when it does not match at all.
///
/// Exported for testing — this is the part that decides whether the
/// palette feels sharp or useless, and it is pure.
export function score(query: string, text: string): number | null {
  const q = query.toLowerCase().trim();
  if (q === "") return 0;

  const t = text.toLowerCase();

  // A prefix or word-start match is what the reader almost always means,
  // so it outranks a subsequence scattered across the string.
  const direct = t.indexOf(q);
  if (direct === 0) return 1000;
  if (direct > 0) return 800 - direct;

  let index = 0;
  let gaps = 0;
  let lastHit = -1;

  for (const char of q) {
    const hit = t.indexOf(char, index);
    if (hit === -1) return null;
    if (lastHit >= 0) gaps += hit - lastHit - 1;
    lastHit = hit;
    index = hit + 1;
  }

  // Fewer characters skipped over means a tighter match.
  return 500 - gaps;
}

export function rank(commands: Command[], query: string): Command[] {
  if (query.trim() === "") return commands;

  return commands
    .map((command) => {
      const haystack = `${command.label} ${command.detail ?? ""} ${command.keywords ?? ""}`;
      return { command, score: score(query, haystack) };
    })
    .filter((entry): entry is { command: Command; score: number } => entry.score !== null)
    .sort((a, b) => b.score - a.score)
    .map((entry) => entry.command);
}

export function isOpen(): boolean {
  return overlay !== null;
}

export function close(): void {
  overlay?.remove();
  overlay = null;
}

export function open(): void {
  if (overlay) return;
  const commands = provider?.() ?? [];

  const input = el("input", {
    class: "palette-input",
    type: "text",
    placeholder: "Jump to a site, or run a command",
    autocomplete: "off",
    spellcheck: false,
    "aria-label": "Command palette",
  });

  const results = el("div", { class: "palette-results", role: "listbox" });
  const panel = el("div", { class: "palette" }, [
    input,
    results,
    el("div", { class: "palette-foot" }, [
      hintKey("↑↓", "move"),
      hintKey("↵", "open"),
      hintKey("esc", "close"),
    ]),
  ]);

  overlay = el("div", { class: "palette-overlay" }, [panel]);

  let matches: Command[] = commands;
  let selected = 0;

  function paint(): void {
    results.replaceChildren();

    if (matches.length === 0) {
      results.append(el("p", { class: "palette-empty", text: "Nothing matches." }));
      return;
    }

    let lastGroup = "";
    matches.forEach((command, index) => {
      if (command.group !== lastGroup) {
        lastGroup = command.group;
        results.append(el("div", { class: "palette-group", text: command.group }));
      }

      const row = el(
        "div",
        {
          class: index === selected ? "palette-item palette-item-on" : "palette-item",
          role: "option",
          "aria-selected": index === selected,
        },
        [
          el("span", { class: "palette-label", text: command.label }),
          command.detail ? el("span", { class: "palette-detail", text: command.detail }) : null,
        ],
      );

      // Pointer users get the same behaviour without having to learn any
      // of this.
      on(row, "mousedown", (event) => {
        event.preventDefault();
        close();
        command.run();
      });
      on(row, "mousemove", () => {
        if (selected === index) return;
        selected = index;
        paint();
      });

      results.append(row);
    });

    results.querySelector(".palette-item-on")?.scrollIntoView({ block: "nearest" });
  }

  paint();

  on(input, "input", () => {
    matches = rank(commands, input.value);
    selected = 0;
    paint();
  });

  on(overlay, "mousedown", (event) => {
    if (event.target === overlay) close();
  });

  document.body.append(overlay);
  input.focus();

  // Keydown is handled on the input rather than the document so the palette
  // owns its keys entirely while it is open, and the page-level shortcuts
  // below cannot fire underneath it.
  on(input, "keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "ArrowDown" || (event.key === "n" && event.ctrlKey)) {
      event.preventDefault();
      selected = matches.length === 0 ? 0 : (selected + 1) % matches.length;
      paint();
      return;
    }
    if (event.key === "ArrowUp" || (event.key === "p" && event.ctrlKey)) {
      event.preventDefault();
      selected = matches.length === 0 ? 0 : (selected - 1 + matches.length) % matches.length;
      paint();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const command = matches[selected];
      if (command) {
        close();
        command.run();
      }
    }
  });
}

function hintKey(key: string, meaning: string): HTMLElement {
  return el("span", { class: "palette-hint" }, [el("kbd", { text: key }), meaning]);
}

/// True when a keystroke belongs to whatever the reader is typing into,
/// rather than to the page.
///
/// Without this, a single-letter shortcut fires while somebody is filling
/// in a domain name, which is the classic way keyboard shortcuts become
/// something users want turned off.
function isTyping(target: EventTarget | null): boolean {
  const node = target as HTMLElement | null;
  if (!node) return false;
  const tag = node.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || node.isContentEditable;
}

/// Wires the page-level shortcuts. Called once at startup.
export function installShortcuts(): void {
  document.addEventListener("keydown", (event) => {
    // Cmd/Ctrl-K works everywhere, including inside a field, because it is
    // unambiguous and is the one people try first.
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      isOpen() ? close() : open();
      return;
    }

    if (isOpen() || isTyping(event.target) || event.metaKey || event.ctrlKey || event.altKey) {
      return;
    }

    if (event.key === "/") {
      event.preventDefault();
      open();
      return;
    }

    if (event.key === "j" || event.key === "ArrowDown") {
      event.preventDefault();
      moveSelection(1);
      return;
    }
    if (event.key === "k" || event.key === "ArrowUp") {
      event.preventDefault();
      moveSelection(-1);
      return;
    }
    if (event.key === "Enter") {
      const current = currentRow();
      if (current) {
        event.preventDefault();
        current.click();
      }
    }
  });
}

/// Rows the arrow keys walk through: whatever the current view marked as
/// navigable. Views do not have to opt in beyond using the class.
function rows(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>("a.entry")];
}

function currentRow(): HTMLElement | undefined {
  return rows().find((row) => row.classList.contains("entry-on"));
}

function moveSelection(delta: number): void {
  const all = rows();
  if (all.length === 0) return;

  const index = all.findIndex((row) => row.classList.contains("entry-on"));
  const next = index === -1 ? (delta > 0 ? 0 : all.length - 1) : (index + delta + all.length) % all.length;

  all.forEach((row) => row.classList.remove("entry-on"));
  all[next]?.classList.add("entry-on");
  all[next]?.scrollIntoView({ block: "nearest" });
}
