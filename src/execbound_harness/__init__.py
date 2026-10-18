# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic policy packs and the validation harness for development checkouts only.

This package lives beside ``execbound`` under ``src`` so the editable development
install can import it, and it is excluded from the runtime wheel and image. Nothing
in the gateway depends on it; ``execbound seed-validation`` imports it lazily.
"""
