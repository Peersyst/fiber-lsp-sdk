import type { IconName } from "./components/Icon";

export interface SiteSection {
    label: string;
    sidebarId: string;
    icon: IconName;
    to: string;
    // Route prefixes whose pages belong to the section; the first match wins, so "/docs" alone goes last.
    paths: string[];
}

// The tabs under the navbar, one per sidebar; the config's mobile menu lists the same ones.
export const SITE_SECTIONS: SiteSection[] = [
    { label: "Get started", sidebarId: "start", icon: "rocket", to: "/docs", paths: ["/docs/get-started"] },
    { label: "Concepts", sidebarId: "concepts", icon: "compass", to: "/docs/concepts/hosted-lsp", paths: ["/docs/concepts"] },
    { label: "Guides", sidebarId: "guides", icon: "book", to: "/docs/guides/register-a-tenant", paths: ["/docs/guides"] },
    { label: "Reference", sidebarId: "reference", icon: "sliders", to: "/docs/reference/options", paths: ["/docs/reference"] },
    { label: "API", sidebarId: "api", icon: "code", to: "/docs/api", paths: ["/docs/api"] },
    { label: "Resources", sidebarId: "resources", icon: "layers", to: "/docs/resources/status", paths: ["/docs/resources"] },
];

/**
 * The section a route belongs to, the introduction's included.
 * @param pathname The route, as the router reports it.
 * @returns The section's sidebar id, or null outside the docs.
 */
export function sectionOf(pathname: string): string | null {
    const path = pathname.replace(/\/$/, "");
    const section = SITE_SECTIONS.find(({ paths }) => paths.some((prefix) => path === prefix || path.startsWith(`${prefix}/`)));
    if (section) return section.sidebarId;
    return path === "/docs" ? "start" : null;
}
