// Charts, drawn as SVG by hand.
//
// No plotting library. The two shapes this product needs are a posture line
// over time and a proportion bar, and a dependency that draws every chart
// ever invented would be larger than the entire application to get them.
//
// Everything here is built with createElementNS and textContent, never
// innerHTML — the values plotted come from scanning somebody else's site.

const NS = "http://www.w3.org/2000/svg";

function svgEl<K extends keyof SVGElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | number> = {},
): SVGElementTagNameMap[K] {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, String(value));
  }
  return node;
}

export interface PosturePoint {
  /// Outstanding items at that moment.
  value: number;
  /// Shown in the tooltip.
  label: string;
}

/// How the number of outstanding problems moved over the last few scans.
///
/// Plotted as a filled area with the points marked, because the shape is
/// the message: a line climbing away from zero is a site being neglected,
/// and that reads instantly in a way a column of numbers never does.
///
/// The vertical scale starts at zero and is never inverted, so two charts
/// on the same page can be compared by eye.
export function postureChart(points: PosturePoint[], width = 560, height = 120): SVGSVGElement {
  const svg = svgEl("svg", {
    viewBox: `0 0 ${width} ${height}`,
    width: "100%",
    height,
    role: "img",
    preserveAspectRatio: "none",
  });

  const title = svgEl("title");
  title.textContent =
    points.length > 1
      ? `Outstanding items across the last ${points.length} scans`
      : "Outstanding items";
  svg.append(title);

  if (points.length === 0) return svg;

  const padX = 2;
  const padY = 14;
  const plotWidth = width - padX * 2;
  const plotHeight = height - padY * 2;

  // A single point has no run to draw, so it is shown as a lone marker
  // rather than a flat line implying history that does not exist.
  const maximum = Math.max(1, ...points.map((point) => point.value));
  const stepX = points.length > 1 ? plotWidth / (points.length - 1) : 0;

  const x = (index: number) => padX + (points.length > 1 ? index * stepX : plotWidth / 2);
  const y = (value: number) => padY + plotHeight - (value / maximum) * plotHeight;

  // A faint baseline: without it a run of zeroes has nothing to sit on and
  // reads as missing data rather than as a clean site.
  svg.append(
    svgEl("line", {
      x1: padX,
      y1: padY + plotHeight,
      x2: width - padX,
      y2: padY + plotHeight,
      stroke: "var(--rule)",
      "stroke-width": 1,
    }),
  );

  if (points.length > 1) {
    const line = points.map((point, index) => `${x(index)},${y(point.value)}`).join(" ");

    svg.append(
      svgEl("polygon", {
        points: `${padX},${padY + plotHeight} ${line} ${width - padX},${padY + plotHeight}`,
        fill: "var(--chart-fill)",
      }),
    );
    svg.append(
      svgEl("polyline", {
        points: line,
        fill: "none",
        stroke: "var(--chart-line)",
        "stroke-width": 2,
        "stroke-linejoin": "round",
        "stroke-linecap": "round",
      }),
    );
  }

  points.forEach((point, index) => {
    const marker = svgEl("circle", {
      cx: x(index),
      cy: y(point.value),
      r: index === points.length - 1 ? 4 : 2.5,
      fill: point.value === 0 ? "var(--clear)" : "var(--chart-line)",
      stroke: "var(--bg)",
      "stroke-width": 1.5,
    });

    const tip = svgEl("title");
    tip.textContent = `${point.value === 0 ? "Clear" : `${point.value} to fix`} · ${point.label}`;
    marker.append(tip);

    svg.append(marker);
  });

  return svg;
}

export interface Slice {
  count: number;
  className: string;
  label: string;
}

/// A proportion bar: how a total splits between ranks.
///
/// Deliberately one bar rather than a pie. The question a reader has is
/// "how much of this is serious", which is a comparison of lengths, and
/// people read lengths accurately and angles badly.
export function proportionBar(slices: Slice[]): HTMLElement {
  const total = slices.reduce((sum, slice) => sum + slice.count, 0);
  const bar = document.createElement("div");
  bar.className = "proportion";

  if (total === 0) return bar;

  for (const slice of slices) {
    if (slice.count === 0) continue;

    const segment = document.createElement("span");
    segment.className = `proportion-part ${slice.className}`;
    // A minimum width so a single low-priority item is still visible
    // rather than rounding away to nothing.
    segment.style.flexBasis = `${Math.max(4, (slice.count / total) * 100)}%`;
    segment.title = `${slice.count} ${slice.label}`;
    bar.append(segment);
  }

  return bar;
}
