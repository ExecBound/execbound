// SPDX-License-Identifier: AGPL-3.0-only
import type { ButtonHTMLAttributes } from "react";

export type ButtonVariant = "default" | "primary" | "danger" | "allow" | "ghost";
export type ButtonSize = "default" | "small" | "decision";

/** 34 px by default; a decision button is 44 px, and 50 px on a phone through the stylesheet. */
export function Button({
  variant = "default",
  size = "default",
  className,
  type = "button",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: ButtonSize }) {
  const classes = ["btn"];
  if (variant !== "default") classes.push(`btn-${variant}`);
  if (size !== "default") classes.push(`btn-${size}`);
  if (className !== undefined) classes.push(className);
  return <button type={type} className={classes.join(" ")} {...rest} />;
}
