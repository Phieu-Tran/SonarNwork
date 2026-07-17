# Package tools page

Package tools share the contextual package rail and a focused task workspace.
The rail remembers the last selected package tool and disappears when the user
moves to another primary view.

- Use package status, install/update affordances, and task controls as the first
  hierarchy; extended documentation is secondary.
- Planned or unavailable actions remain understandable through copy and
  `aria-disabled`, even when the card is still selectable for explanation.
- Preserve tool-specific risk labels, bounded profiles, and command previews;
  target actions run directly once their required input is valid. Bounded
  profiles allow users to select appropriate scanning depth without needing
  to manually confirm every stage of high-risk operations.
- At compact widths the package rail becomes an icon rail with accessible names
  so the task panel retains most of the window.
