import MDXComponents from "@theme-original/MDXComponents";

import CardGrid, { Card } from "../components/CardGrid";

// Cards are used across the docs, so every MDX page gets them without an import.
export default { ...MDXComponents, Card, CardGrid };
