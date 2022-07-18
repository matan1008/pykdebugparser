from dataclasses import dataclass
from enum import Enum
from typing import List


class TurnstileType(Enum):
    TURNSTILE_NONE = 0
    TURNSTILE_KERNEL_MUTEX = 1
    TURNSTILE_ULOCK = 2
    TURNSTILE_PTHREAD_MUTEX = 3
    TURNSTILE_SYNC_IPC = 4
    TURNSTILE_WORKLOOPS = 5
    TURNSTILE_WORKQS = 6
    TURNSTILE_KNOTE = 7
    TURNSTILE_SLEEP_INHERITOR = 8
    TURNSTILE_TOTAL_TYPES = 9


@dataclass
class ThreadRemovedFromTurnstileWaitq:
    ktraces: List
    turnstile: int
    tid: int

    def __str__(self):
        return f'thread_removed_from_turnstile_waitq, turnstile: {hex(self.turnstile)}, tid: {self.tid}'


@dataclass
class AddedFromThreadHeap:
    ktraces: List
    tid: int
    turnstile: int
    priority: int

    def __str__(self):
        return f'thread_add_turnstile_promotion({self.tid}, {hex(self.turnstile)}), priority: {self.priority}'


@dataclass
class RemovedFromThreadHeap:
    ktraces: List
    tid: int
    turnstile: int

    def __str__(self):
        return f'thread_remove_turnstile_promotion({self.tid}, {hex(self.turnstile)})'


@dataclass
class TurnstilePrepare:
    ktraces: List
    turnstile: int
    proprietor: int
    type_: TurnstileType

    def __str__(self):
        return (f'turnstile_prepare, turnstile: {hex(self.turnstile)}, proprietor: {hex(self.proprietor)}, '
                f'type: {self.type_.name}')


@dataclass
class TurnstileComplete:
    ktraces: List
    turnstile: int
    proprietor: int
    type_: TurnstileType

    def __str__(self):
        return (f'turnstile_complete, turnstile: {hex(self.turnstile)}, proprietor: {hex(self.proprietor)}, '
                f'type: {self.type_.name}')


def handle_turnstile_thread_removed_from_turnstile_waitq(parser, events):
    return ThreadRemovedFromTurnstileWaitq(events, *events[0].values[:2])


def handle_turnstile_added_from_thread_heap(parser, events):
    return AddedFromThreadHeap(events, *events[0].values[:3])


def handle_turnstile_removed_from_thread_heap(parser, events):
    return RemovedFromThreadHeap(events, *events[0].values[:2])


def handle_turnstile_turnstile_prepare(parser, events):
    return TurnstilePrepare(events, *events[0].values[:2], TurnstileType(events[0].values[2]))


def handle_turnstile_turnstile_complete(parser, events):
    return TurnstileComplete(events, *events[0].values[:2], TurnstileType(events[0].values[2]))


handlers = {
    'TURNSTILE_thread_removed_from_turnstile_waitq': handle_turnstile_thread_removed_from_turnstile_waitq,
    'TURNSTILE_turnstile_added_to_thread_heap': handle_turnstile_added_from_thread_heap,
    'TURNSTILE_turnstile_removed_from_thread_heap': handle_turnstile_removed_from_thread_heap,
    'TURNSTILE_turnstile_prepare': handle_turnstile_turnstile_prepare,
    'TURNSTILE_turnstile_complete': handle_turnstile_turnstile_complete,
}
