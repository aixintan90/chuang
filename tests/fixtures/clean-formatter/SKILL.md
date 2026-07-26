---
name: clean-formatter
description: Formats Markdown tables so columns line up, using only local text processing. No network, no scripts.
---

# Markdown Table Formatter

When the user has a messy Markdown table, realign it.

## What happened

Markdown tables become unreadable when the pipes don't line up.

## How to do it

1. Parse each row into cells by splitting on `|`.
2. Compute the maximum width of each column.
3. Pad every cell to its column width and re-emit the table.

This is pure string manipulation — no commands, no files beyond the one the
user is editing, no network access.
