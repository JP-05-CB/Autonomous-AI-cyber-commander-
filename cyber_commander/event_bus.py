import queue


class EventBus:

    def __init__(self):
        self.event_queue = queue.Queue()

    def publish(self, event):
        print(
            f"[EVENT BUS] Publishing event: "
            f"{event.event_type}"
        )

        self.event_queue.put(event)

    def get_event(self):
        return self.event_queue.get()

    def has_events(self):
        return not self.event_queue.empty()
