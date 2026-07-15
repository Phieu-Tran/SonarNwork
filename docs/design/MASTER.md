# SonarNwork design system

SonarNwork is a Windows network-diagnostics workbench. Its interface should feel
precise, calm, and operational: the current task, its safety boundary, and its
result must be easier to find than decorative or secondary information.

## Design dials

- Visual variance: 5/10. Use signal-blue application chrome, quiet layered
  surfaces, and a restrained technical-grid backdrop; reserve saturated
  workflow colors for direction, status, and the primary action.
- Motion: 2/10. Interaction feedback lasts about 160 ms. Continuous motion is
  limited to progress indicators and must respect reduced-motion preferences.
- Information density: 7/10. Dense enough for operators, but never below 11 px
  for supporting labels or 12 px for meaningful body copy.

## Foundations

The UI uses Segoe UI Variable Text/Segoe UI for interface copy and Cascadia
Mono/Consolas for commands and machine output. Use the existing 4/8 px spacing
rhythm, 4-5 px control radii, and one-pixel semantic borders.

All colors come from semantic CSS tokens in `app/src/styles.css`. The light
theme uses cool slate surfaces with signal blue; the dark theme uses
graphite/navy surfaces with cyan interaction highlights. Text and control
labels must meet WCAG AA contrast in both themes. Direction colors (teal local,
blue outbound, green public, violet lookup) supplement an icon or label and
never carry meaning alone. Warning amber and danger rose are reserved for their
semantic roles. Primary and destructive controls use `--on-accent` and
`--on-danger` for their foregrounds.

Use one boundary per hierarchy level. Main work surfaces are flat, square-edged
panels separated by a semantic top rule; nested content uses dividers, a soft
background, or a left status rule instead of another complete frame. Shadows
are not part of the normal hierarchy. Inputs and actionable buttons may keep a
small radius because their boundary communicates interaction. The grid backdrop
belongs to the workspace only and must remain faint enough that logs, forms,
and results keep visual priority.

## Navigation model

The product has four primary views:

1. Diagnose selects a diagnostic workflow, including Globalping.
2. Tools opens installable package workflows and exposes the package rail.
3. Operations contains controlled capture, monitor, inventory, and command
   operations.
4. History contains saved runs and comparisons.

The package rail is contextual. It must not consume space in Diagnose,
Operations, or History. Package identity uses the bundled official logo assets;
two-letter monograms are only a technical fallback when an image cannot load.

## Component rules

- Every button has a visible hover, pressed, focus, and disabled state.
- The primary action is unique within its local panel. Stop/destructive actions
  remain visually distinct.
- Selected checks expose `aria-pressed`; selected navigation exposes
  `aria-current`.
- Error banners use `role="alert"`; asynchronous loading copy uses
  `role="status"` where appropriate.
- Empty states answer three questions: what is absent, why that is expected,
  and what the operator can do next.
- Commands, logs, addresses, ports, and identifiers use the mono font and
  tabular numerals where useful.
- Avoid box-in-box layouts. Rows inside navigation, result lists, histories,
  and empty states use separators or a single status edge, not repeated rounded
  cards.
- The primary diagnostic workflow picker uses the themed listbox component,
  with Arrow keys, Home/End, Enter, and Escape support; do not replace it with
  an unstyled platform select.

## Responsive behavior

At wide widths the diagnostic page uses a sticky check rail beside the active
stage. Below 840 px, the rail becomes a compact select so configuration, run
controls, and results remain above the fold. Tool pages retain a narrow icon
rail only when needed; operations stacks to one column below 980 px. No primary
control should require horizontal page scrolling at 520 px or wider.

## Verification

Changes that affect the interface must pass `pnpm test` and `pnpm build` from
`app/`. Review Diagnose, Tools, Operations, and History at desktop and compact
window widths, in both themes when color tokens change. Check keyboard focus,
empty/loading/error states, and an accessibility audit before release.
