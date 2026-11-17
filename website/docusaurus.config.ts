import type * as Preset from "@docusaurus/preset-classic";
import type { Config } from "@docusaurus/types";
import { themes as prismThemes } from "prism-react-renderer";

import { SITE_SECTIONS } from "./src/sections";

const REPO_URL = "https://github.com/Peersyst/fiber-lsp-sdk";

const config: Config = {
    title: "Fiber LSP SDK",
    tagline: "Self-custodial Lightning on CKB for mobile wallets, with the node hosted at an LSP.",
    favicon: "img/favicon.svg",
    url: "https://fiber-lsp-sdk.vercel.app",
    baseUrl: "/",
    organizationName: "Peersyst",
    projectName: "fiber-lsp-sdk",
    trailingSlash: false,
    onBrokenLinks: "throw",
    onBrokenAnchors: "throw",
    i18n: { defaultLocale: "en", locales: ["en"] },
    markdown: {
        mermaid: true,
        hooks: { onBrokenMarkdownLinks: "throw" },
    },
    themes: [
        "@docusaurus/theme-mermaid",
        [
            "@easyops-cn/docusaurus-search-local",
            {
                hashed: true,
                indexBlog: false,
                docsRouteBasePath: "/docs",
                highlightSearchTermsOnTargetPage: true,
                searchBarShortcutHint: true,
            },
        ],
    ],
    plugins: [
        [
            "docusaurus-plugin-typedoc",
            {
                name: "API Reference",
                entryPoints: ["../src/index.ts"],
                tsconfig: "../tsconfig.json",
                out: "docs/api",
                readme: "none",
                excludePrivate: true,
                excludeInternal: true,
                disableSources: false,
                sourceLinkTemplate: `${REPO_URL}/blob/main/{path}#L{line}`,
                gitRevision: "main",
                parametersFormat: "table",
                interfacePropertiesFormat: "table",
                typeDeclarationFormat: "table",
                enumMembersFormat: "table",
                useCodeBlocks: true,
                expandObjects: true,
                hidePageHeader: true,
                hideBreadcrumbs: true,
                sidebar: { pretty: true },
            },
        ],
    ],
    presets: [
        [
            "classic",
            {
                docs: {
                    sidebarPath: "./sidebars.ts",
                    editUrl: `${REPO_URL}/edit/main/website/`,
                    showLastUpdateTime: false,
                },
                blog: false,
                theme: { customCss: ["./src/css/custom.css", "./src/css/icons.css"] },
            } satisfies Preset.Options,
        ],
    ],
    themeConfig: {
        image: "img/social-card.svg",
        colorMode: { defaultMode: "dark", respectPrefersColorScheme: true },
        docs: { sidebar: { hideable: false, autoCollapseCategories: false } },
        navbar: {
            title: "Fiber LSP SDK",
            logo: { alt: "Fiber LSP SDK", src: "img/logo.svg", srcDark: "img/logo-dark.svg" },
            items: [
                { type: "search", position: "left" },
                // The tabs row draws these on desktop; the mobile menu lists them.
                ...SITE_SECTIONS.map(({ label, sidebarId }) => ({
                    type: "docSidebar" as const,
                    sidebarId,
                    label,
                    position: "left" as const,
                    className: "navbar-section-item",
                })),
                { href: REPO_URL, position: "right", className: "header-github-link", "aria-label": "GitHub repository" },
            ],
        },
        footer: {
            style: "light",
            links: [
                {
                    title: "Learn",
                    items: [
                        { label: "Introduction", to: "/docs" },
                        { label: "Quickstart", to: "/docs/get-started/quickstart" },
                        { label: "Concepts", to: "/docs/concepts/hosted-lsp" },
                    ],
                },
                {
                    title: "Build",
                    items: [
                        { label: "Guides", to: "/docs/guides/register-a-tenant" },
                        { label: "API Reference", to: "/docs/api" },
                        { label: "React Native", to: "/docs/guides/react-native" },
                    ],
                },
                {
                    title: "Project",
                    items: [
                        { label: "GitHub", href: REPO_URL },
                        { label: "Fiber", href: "https://github.com/nervosnetwork/fiber" },
                        { label: "Status", to: "/docs/resources/status" },
                    ],
                },
            ],
            copyright: `© ${new Date().getFullYear()} Peersyst.`,
        },
        prism: {
            theme: prismThemes.github,
            darkTheme: prismThemes.oneDark,
            additionalLanguages: ["bash", "json", "rust"],
        },
        mermaid: { theme: { light: "neutral", dark: "dark" } },
        tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
    } satisfies Preset.ThemeConfig,
};

export default config;
