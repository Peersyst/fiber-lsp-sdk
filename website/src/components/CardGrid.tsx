import Link from "@docusaurus/Link";
import type { ReactNode } from "react";

import Icon, { type IconName } from "./Icon";

export interface CardProps {
    title: string;
    children: ReactNode;
    icon?: IconName;
    to?: string;
    cta?: string;
}

/**
 * A card with an icon, a title and a short text, a link when `to` is given.
 * @param props The card's content.
 * @param props.title Its heading.
 * @param props.children Its text.
 * @param props.icon The icon above the heading, if any.
 * @param props.to Where it links, if anywhere.
 * @param props.cta The call to action under the text, if any.
 * @returns The card.
 */
export function Card({ title, children, icon, to, cta }: CardProps): ReactNode {
    const content = (
        <>
            {icon && (
                <span className="doc-card__icon">
                    <Icon name={icon} size={22} />
                </span>
            )}
            <span className="doc-card__title">{title}</span>
            <span className="doc-card__body">{children}</span>
            {cta && (
                <span className="doc-card__cta">
                    {cta}
                    <Icon name="chevron-right" size={14} />
                </span>
            )}
        </>
    );
    return to ? (
        <Link className="doc-card" to={to}>
            {content}
        </Link>
    ) : (
        <div className="doc-card">{content}</div>
    );
}

/**
 * A responsive grid of cards.
 * @param props The grid's cards.
 * @param props.children The `Card`s it lays out.
 * @returns The grid.
 */
export default function CardGrid({ children }: { children: ReactNode }): ReactNode {
    return <div className="card-grid">{children}</div>;
}
