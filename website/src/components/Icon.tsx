import useBaseUrl from "@docusaurus/useBaseUrl";
import type { CSSProperties, ReactNode } from "react";

// One per file in static/img/icons/, which the sidebar's CSS masks too: the set has a single source.
export const ICON_NAMES = [
    "alert",
    "arrow-down",
    "arrow-up",
    "arrow-up-right",
    "bell",
    "bolt",
    "book",
    "chevron-right",
    "code",
    "compass",
    "database",
    "devices",
    "eye",
    "flag",
    "globe",
    "hash",
    "help",
    "home",
    "key",
    "layers",
    "link",
    "list",
    "lock",
    "moon",
    "package",
    "phone",
    "refresh",
    "rocket",
    "scan",
    "server",
    "shield",
    "sliders",
    "user-plus",
    "x-circle",
] as const;

export type IconName = (typeof ICON_NAMES)[number];

/**
 * One of the site's stroke icons, drawn in the current text color.
 * @param props The icon's name and its size in pixels.
 * @param props.name Which icon to draw.
 * @param props.size Its width and height, 20 by default.
 * @returns The icon.
 */
export default function Icon({ name, size = 20 }: { name: IconName; size?: number }): ReactNode {
    const url = `url(${useBaseUrl(`/img/icons/${name}.svg`)})`;
    const style: CSSProperties = { width: size, height: size, maskImage: url, WebkitMaskImage: url };
    return <span className="site-icon" style={style} aria-hidden="true" />;
}
