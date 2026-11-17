import Link from "@docusaurus/Link";
import CodeBlock from "@theme/CodeBlock";
import Layout from "@theme/Layout";
import clsx from "clsx";
import type { ReactNode } from "react";

import CardGrid, { Card } from "../components/CardGrid";
import Icon, { type IconName } from "../components/Icon";
import styles from "./index.module.css";

const DEVICE_SNIPPET = `import { FiberLspSdk, deriveMasterSeed } from "@peersyst/fiber-lsp-sdk";

const sdk = new FiberLspSdk(deriveMasterSeed(bip39Seed), {
    network: "testnet",
    rpcUrl: "https://lsp.example.com/rpc",
    lspPubkey,
    storage,
});

sdk.onEvent((event) => console.log(event.type));
sdk.connect();`;

const OPERATOR_SNIPPET = `import { LspOperatorClient, verifyTenantRegistration } from "@peersyst/fiber-lsp-sdk";

const operator = new LspOperatorClient({ rpcUrl, operatorToken });

if (!verifyTenantRegistration(lspPubkey, registration)) {
    throw new Error("registration not signed by its device");
}
const { tenantId, accessToken } = await operator.registerTenant(registration);`;

const FEATURES: { icon: IconName; title: string; body: ReactNode }[] = [
    {
        icon: "shield",
        title: "Never blind-signs",
        body: "Every request is rebuilt from what the device knows and checked against its policy before a signature exists.",
    },
    {
        icon: "key",
        title: "Recoverable from the seed",
        body: "Every channel key and nonce is a deterministic function of one master seed, derived from the wallet's mnemonic.",
    },
    {
        icon: "devices",
        title: "Runs everywhere",
        body: "The same code in Node, browsers and React Native (Hermes), with no polyfills and no platform calls of its own.",
    },
    {
        icon: "package",
        title: "Four audited dependencies",
        body: "Only the noble and scure libraries: curves, hashes, BIP32 and the Bitcoin signer.",
    },
    {
        icon: "lock",
        title: "Sign once, by design",
        body: "Deterministic musig2 nonces and a persisted sign-once registry: one message per slot, never two.",
    },
    {
        icon: "eye",
        title: "Watchtower under your rules",
        body: "After a force close, a spend is signed only toward the destination and fee the host approved.",
    },
];

/**
 * One row of the landing's quick starts: the text on one side, the code on the other.
 * @param props The row's content.
 * @param props.title Its heading.
 * @param props.body Its text.
 * @param props.links The links under the text.
 * @param props.code The sample.
 * @param props.file The sample's file name.
 * @param props.reverse Whether the code goes first.
 * @returns The row.
 */
function StartRow({
    title,
    body,
    links,
    code,
    file,
    reverse = false,
}: {
    title: string;
    body: string;
    links: { label: string; to: string }[];
    code: string;
    file: string;
    reverse?: boolean;
}): ReactNode {
    return (
        <div className={clsx(styles.startRow, reverse && styles.startRowReverse)}>
            <div className={styles.startText}>
                <h2>{title}</h2>
                <p>{body}</p>
                {links.map((link) => (
                    <Link key={link.to} className={styles.startLink} to={link.to}>
                        {link.label} →
                    </Link>
                ))}
            </div>
            <div className={styles.startCode}>
                <CodeBlock language="ts" title={file}>
                    {code}
                </CodeBlock>
            </div>
        </div>
    );
}

/**
 * The landing page: what the SDK is, the two ways in, why it is built the way it is, and the map of the docs.
 * @returns The page.
 */
export default function Home(): ReactNode {
    return (
        <Layout
            title="Developer docs"
            description="The device signer SDK for Fiber hosted-LSP integrations: the LSP runs the node, the wallet holds the keys."
        >
            <main className={styles.main}>
                <header className={styles.hero}>
                    <div className={styles.badges}>
                        <span className={styles.badge}>
                            <Icon name="bolt" size={13} /> Fiber hosted LSP
                        </span>
                        <span className={styles.badge}>
                            <Icon name="flag" size={13} /> Pre-release
                        </span>
                    </div>
                    <h1 className={styles.title}>Fiber LSP SDK Docs</h1>
                    <p className={styles.subtitle}>
                        Give a wallet the keys of Fiber channels hosted at an LSP. The LSP runs the node; the device signs only what it has
                        rebuilt and checked.
                    </p>
                </header>

                <section className={styles.starts}>
                    <StartRow
                        title="Build the wallet side"
                        body="One FiberLspSdk per seed: it registers the device, opens channels, receives and sends payments, and answers the node's signing requests in the background."
                        links={[
                            { label: "What is a hosted LSP?", to: "/docs/concepts/hosted-lsp" },
                            { label: "Quickstart", to: "/docs/get-started/quickstart" },
                        ]}
                        code={DEVICE_SNIPPET}
                        file="wallet.ts"
                    />
                    <StartRow
                        title="Run the LSP side"
                        body="The operator's backend verifies a device's signed registration and gets it a tenant token from the node, with the same package."
                        links={[
                            { label: "Register a tenant", to: "/docs/guides/register-a-tenant" },
                            { label: "Security model", to: "/docs/resources/security" },
                        ]}
                        code={OPERATOR_SNIPPET}
                        file="backend.ts"
                        reverse
                    />
                </section>

                <section className={styles.section}>
                    <h2 className={styles.sectionTitleCentered}>Why the Fiber LSP SDK?</h2>
                    <div className={styles.features}>
                        {FEATURES.map((feature) => (
                            <div key={feature.title} className={styles.feature}>
                                <span className={styles.featureIcon}>
                                    <Icon name={feature.icon} size={22} />
                                </span>
                                <div>
                                    <div className={styles.featureTitle}>{feature.title}</div>
                                    <div className={styles.featureBody}>{feature.body}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </section>

                <section className={styles.section}>
                    <h2 className={styles.sectionTitle}>Browse the docs</h2>
                    <CardGrid>
                        <Card icon="rocket" title="Get started" to="/docs" cta="Start building">
                            What the SDK is, how to install it, and a wallet running in a few minutes.
                        </Card>
                        <Card icon="compass" title="Concepts" to="/docs/concepts/hosted-lsp" cta="Learn the model">
                            The hosted-LSP model, keys and recovery, the signing policy, the poller and storage.
                        </Card>
                        <Card icon="book" title="Guides" to="/docs/guides/register-a-tenant" cta="Follow a guide">
                            Register, open a channel, receive, send, close, and ship it in React Native.
                        </Card>
                        <Card icon="sliders" title="Reference" to="/docs/reference/options" cta="Look it up">
                            Options, the eleven events, error codes and constants, in tables.
                        </Card>
                        <Card icon="code" title="API Reference" to="/docs/api" cta="Browse the API">
                            Every class, function and type the package exports, generated from its source.
                        </Card>
                        <Card icon="flag" title="Status" to="/docs/resources/status" cta="Read the status">
                            What works today, what Fiber still has to change, and what the SDK does not do.
                        </Card>
                    </CardGrid>
                </section>
            </main>
        </Layout>
    );
}
