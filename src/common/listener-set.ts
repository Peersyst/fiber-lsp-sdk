export class ListenerSet<Event> {
    private readonly listeners = new Set<(event: Event) => void>();

    /**
     * Subscribes a listener.
     * @param listener The listener; whatever it throws is swallowed.
     * @returns A function that unsubscribes it.
     */
    add(listener: (event: Event) => void): () => void {
        this.listeners.add(listener);
        return () => {
            this.listeners.delete(listener);
        };
    }

    /**
     * Delivers an event to the listeners subscribed when it is raised; one that throws never stops the others.
     * @param event The event.
     */
    emit(event: Event): void {
        for (const listener of [...this.listeners]) {
            try {
                listener(event);
            } catch {
                // A listener's failure is the host's, not the SDK's.
            }
        }
    }
}
