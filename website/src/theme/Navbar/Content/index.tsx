import Link from "@docusaurus/Link";
import { useLocation } from "@docusaurus/router";
import type { WrapperProps } from "@docusaurus/types";
import Content from "@theme-original/Navbar/Content";
import type ContentType from "@theme/Navbar/Content";
import clsx from "clsx";
import type { ReactNode } from "react";

import Icon from "../../../components/Icon";
import { SITE_SECTIONS, sectionOf } from "../../../sections";

type Props = WrapperProps<typeof ContentType>;

/**
 * The second row of the navbar: one tab per section, the current one underlined.
 * @returns The tab row.
 */
function SectionTabs(): ReactNode {
    const { pathname } = useLocation();
    const active = pathname === "/" ? "home" : sectionOf(pathname);
    return (
        <div className="section-tabs">
            <Link className={clsx("section-tab", active === "home" && "section-tab--active")} to="/">
                <Icon name="home" size={16} />
                Home
            </Link>
            {SITE_SECTIONS.map((section) => (
                <Link
                    key={section.sidebarId}
                    className={clsx("section-tab", active === section.sidebarId && "section-tab--active")}
                    to={section.to}
                >
                    <Icon name={section.icon} size={16} />
                    {section.label}
                </Link>
            ))}
        </div>
    );
}

/**
 * The theme's navbar content with the section tabs under it.
 * @param props The original content's props.
 * @returns Both rows.
 */
export default function ContentWrapper(props: Props): ReactNode {
    return (
        <div className="navbar-rows">
            <Content {...props} />
            <SectionTabs />
        </div>
    );
}
